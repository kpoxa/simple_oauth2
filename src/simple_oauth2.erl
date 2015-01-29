-module(simple_oauth2).
-author('Igor Milyakov <virtan@virtan.com>').

-export([dispatcher/3, dispatch_action/2,  compose_get_url/1, request/4, join_query_args/1]).
-define(REDIRECT_SCRIPT, <<"<!--script>window.location.replace(window.location.href.replace('#','?'))</script-->">>).
-import(proplists, [get_value/2, get_value/3]).

-include("../include/simple_oauth2.hrl").

parse_query_parameters(<<>>) -> [];
parse_query_parameters(QueryString) ->
    [{list_to_binary(K), list_to_binary(V)} ||
        {K, V} <- httpd:parse_query(binary_to_list(QueryString))].

dispatcher(Request, LocalUrlPrefix, Networks) -> 
    [Path | [Query]] = binary:split(Request, <<"?">>),
    [NetName, Action] = binary:split(Path, <<"/">>),
    RqParams = parse_query_parameters(Query),
    Network = get_value(NetName, Networks),
    Req = #req{ network_name = NetName, network_settings = Network, url_prefix = LocalUrlPrefix, req_params = RqParams}, 
    dispatch_action(Action, Req).

request(NetworkName, NetworkSettings, Uri, LocalUrlPrefix) ->
    Network = get_value(NetworkName, NetworkSettings),
    [_Path | [Query] ] = binary:split(Uri, <<"?">>),
    RqParams = parse_query_parameters(Query),
    #req{ network_name = NetworkName, network_settings = Network, url_prefix = LocalUrlPrefix, req_params = RqParams}.


dispatch_action(undefined, _) ->
    {error, unknown_network, "Unknown or not customized social network"};
dispatch_action(<<"login">>, Req) ->
    {redirect,
        {get_authorize_uri(Req#req.network_settings), get_redirect_params(Req) }
    };
dispatch_action(<<"callback">>, Req) ->
    check_error_and_dispatch(get_error(Req), Req).


check_error_and_dispatch(undefined, Req) ->
    dispatch(get_code(Req), Req);
check_error_and_dispatch(Error, _) ->
    {error, auth_error, Error}.

dispatch(undefined, Req) ->
    dispatch_access_token(get_access_token(Req), Req);
dispatch(Code, Req) ->
    post(Req, get_token_uri(Req), [
        {code, Code},
        get_client_id(Req),
        get_client_secret(Req),
        get_redirect_uri(Req),
        {grant_type, <<"authorization_code">>}
    ]).

dispatch_access_token(undefined, _) ->
    {send_html, ?REDIRECT_SCRIPT};
dispatch_access_token(Token, Req) -> 
    {ok, 
        get_profile_info(Req, 
            [
                {network, Req#req.network_name},
                {access_token, Token},
                get_token_type(Req)
            ])
    }.


get_redirect_params(Req) ->
    [get_client_id(Req),
     get_redirect_uri(Req),
     get_response_type(Req),
     get_scope(Req),
     get_state(Req)].

get_userinfo_composer(Network) ->
    get_value(userinfo_composer, Network).

get_userinfo_params(Network) ->
    get_value(userinfo_params, Network).

get_userinfo_uri(Network) ->
    get_value(userinfo_uri, Network).

get_access_token(#req { req_params = RqParams } ) ->
    get_value(<<"access_token">>, RqParams, undefined).

get_token_uri(#req { network_settings = Network}) ->
    get_value(token_uri, Network).

get_code(#req { req_params = RqParams }) ->
    get_value(<<"code">>, RqParams, undefined).

get_error(#req { req_params = RqParams }) ->
    get_value(<<"error">>, RqParams, undefined).

get_token_type(#req { req_params = RqParams }) ->
    {token_type, get_value(<<"token_type">>, RqParams, <<"bearer">>)}.

get_client_secret(#req { network_settings = Network}) ->
    {client_secret, get_value(client_secret, Network)}.

get_client_id(#req { network_settings = Network}) ->
    {client_id, get_value(client_id, Network)}.

get_scope(#req { network_settings = Network}) ->
    {scope, get_value(scope, Network)}.

get_state(#req { req_params = RqParams }) ->
    {state, get_value(<<"state">>, RqParams, <<>>)}.

get_response_type(#req { req_params = RqParams }) ->
    {response_type, get_value(<<"response_type">>, RqParams, <<"code">>)}.

get_redirect_uri(#req { url_prefix = LocalUrlPrefix, network_settings = Network }) ->
    {redirect_uri, iolist_to_binary([LocalUrlPrefix, get_value(callback_uri, Network)])}.

get_authorize_uri(#req { network_settings = Network}) ->
    get_value(authorize_uri, Network).

urlencoded_parse(Data) ->
    Parsed = parse_query_parameters(Data),
    ParsedLength = length(Parsed),
    CleanLength = length([{K, V} || {K, V} <- Parsed, K =/= <<>>, V =/= <<>>]),
    if
        CleanLength == ParsedLength -> Parsed;
        true -> {error, json_error, "Can't parse json"}
    end.

json_parse(JSON) ->
    case jsx:decode(JSON, [{error_handler, fun(_, _, _) -> {error, unsuccessful} end}]) of
        {error, _} -> urlencoded_parse(JSON);
        {incomplete, _} -> urlencoded_parse(JSON);
        Parsed -> Parsed
    end.

http_request_json(Method, Request, OnSuccess) ->
    handle_response(do_request(Method, Request), OnSuccess).

handle_response({ok, {200, JSON}}, OnSuccess) -> 
    OnSuccess(JSON);
handle_response({ok, {Code, Ret}}, _) -> 
    {error, post_error, lists:flatten("Post returned non-200 code: " ++
            integer_to_list(Code) ++ " " ++ binary_to_list(Ret))};
handle_response({error, Reason}, _) -> 
    {error, http_request_error, Reason}.
    

do_request(Method, Request) ->
    httpc:request(Method, Request,
            [{timeout, 10000}, {connect_timeout, 20000}, {autoredirect, true}],
            [{body_format, binary}, {full_result, false}]).

post(Req, Url, Params) ->
    http_request_json(post, {binary_to_list(Url), [], "application/x-www-form-urlencoded",
            url_encode(Params)},
        fun(JSON) -> case json_parse(JSON) of
                {error, _, _} = Error -> Error;
                Hash -> case get_value(<<"error">>, Hash, undefined) of
                            undefined -> {ok, get_profile_info(Req, create_auth_info(Req, Hash))};
                            Error -> {error, unsuccessful, Error}
                    end
            end
        end).

create_auth_info(Req, Hash) ->
    [{network, Req#req.network_name },
     {access_token, get_value(<<"access_token">>, Hash)},
     {token_type, get_value(<<"token_type">>, Hash, <<"bearer">>)}].

url_encode(Data) -> url_encode(Data,"").
url_encode([],Acc) -> list_to_binary(Acc);
url_encode([{Key,Value}|R],"") ->
url_encode(R, simple_oauth2_utils:encode(atom_to_list(Key)) ++ "=" ++
 simple_oauth2_utils:encode(binary_to_list(Value)));
url_encode([{Key,Value}|R],Acc) ->
    url_encode(R, Acc ++ "&" ++ simple_oauth2_utils:encode(atom_to_list(Key)) ++ "=" ++
        simple_oauth2_utils:encode(binary_to_list(Value))).



join_query_args(QueryArgs) ->
    Pairs = [[simple_oauth2_utils:encode(Key), "=", simple_oauth2_utils:encode(Value)] || {Key, Value} <- QueryArgs],
    ["?" | string:join(Pairs, "&")].

get_profile_info(#req { network_settings = Network}, Auth) ->
    Url = compose_get_profile_url(Network, Auth),
    Request = {Url, []},
    http_request_json(get, Request, fun(JSON) -> prepare_parsed_profile(json_parse(JSON), Network, Auth) end).

get_patch_profile_callback(Network) ->
    get_value(field_pre, Network).

get_field_names(Network) ->
    lists:zip([id, email, name, picture, gender, locale], get_value(field_names, Network)).

fix_profile(Profile, undefined) -> Profile;
fix_profile(Profile, Callback) -> Callback(Profile).

get_field_from_profile(Name, Profile) when is_atom(Name) ->
    get_value(list_to_binary(atom_to_list(Name)), Profile).

get_field_fix(Network) ->
    get_value(field_fix, Network).

fix_profile_field(Name, Profile, Network) ->
    fix_field(get_field_fix(Network), Name, Profile).

fix_field(undefined, Name, Profile) -> 
    get_field_from_profile(Name, Profile);
fix_field(Func, Name, Profile) when is_function(Func) -> 
    Func(Name, Profile, fun(N, P) -> get_field_from_profile(N, P) end).

get_profile_fields(Profile, Network) ->
    [{Field, fix_profile_field(Name, Profile, Network)} || {Field, Name} <- get_field_names(Network)].

prepare_parsed_profile({error, _, _} = Error, _, _) -> 
    Error;
prepare_parsed_profile(Profile, Network, Auth) -> 
    FixedProfile = fix_profile(Profile, get_patch_profile_callback(Network)),
    ProfileFields = get_profile_fields(FixedProfile, Network), 
    ProfileFields ++ [{raw, Profile} | Auth].

compose_get_profile_url(Network, Auth) ->
    Path = get_userinfo_uri(Network),
    Args = compose_get_profile_query_args(get_userinfo_composer(Network), Auth, Network),
    compose_get_url({Path, Args}).

compose_get_url({Path, QueryString}) ->
    QueryArgs = join_query_args(QueryString),
    binary_to_list(iolist_to_binary([Path | QueryArgs])).

compose_get_profile_query_args(undefined, Auth, Network) ->
    Params = get_userinfo_params(Network),
    lists:map(fun({K, access_token}) -> 
                        {K, get_value(access_token, Auth)};
                  (P) -> P 
              end, Params);
compose_get_profile_query_args(Callback, Auth, Network) ->
    Callback(Auth, Network).