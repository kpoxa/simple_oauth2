-module(simple_oauth2).
-author('Igor Milyakov <virtan@virtan.com>').

-export([dispatcher/3, dispatch_action/2, predefined_networks/0, customize_networks/2, gather_url_get/1]).
-define(REDIRECT_SCRIPT, <<"<!--script>window.location.replace(window.location.href.replace('#','?'))</script-->">>).
-import(proplists, [get_value/2, get_value/3]).

-include("../include/simple_oauth2.hrl").

customize_networks(Networks, Customization) ->
    [
        {Network, fun() ->
           CustOpts = get_value(Network, Customization),
           {_, Rem} = proplists:split(Options, proplists:get_keys(CustOpts)),
           CustOpts ++ Rem
           end()}
        || {Network, Options} <- Networks,
           get_value(Network, Customization, undefined) =/= undefined
    ].

parse_gets(<<>>) -> [];
parse_gets(GetString) ->
    [{list_to_binary(K), list_to_binary(V)} ||
        {K, V} <- httpd:parse_query(binary_to_list(GetString))].

dispatcher(Request, LocalUrlPrefix, Networks) -> 
    [Path | PreGets] = binary:split(Request, <<"?">>),
    [NetName, Action] = binary:split(Path, <<"/">>),
    RqParams = case PreGets of
        [] -> [];
        [QString] -> parse_gets(QString)
    end,
    Network = get_value(NetName, Networks),
    Req = #req{ network_name = NetName, network_settings = Network, url_prefix = LocalUrlPrefix, req_params = RqParams}, 
    dispatch_action(Action, Req).

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
    post({Req#req.network_name, Req#req.network_settings}, get_token_uri(Req), [
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
    Parsed = parse_gets(Data),
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
    case httpc:request(Method, Request,
            [{timeout, 10000}, {connect_timeout, 20000}, {autoredirect, true}],
            [{body_format, binary}, {full_result, false}]) of
        {ok, {200, JSON}} -> OnSuccess(JSON);
        {ok, {Code, _Ret}} -> {error, post_error, lists:flatten("Post returned non-200 code: " ++
                    integer_to_list(Code) ++ _Ret)};
        {error, Reason} -> {error, http_request_error, Reason}
    end.

post({NetName, Network}, Url, Params) ->
    http_request_json(post, {binary_to_list(Url), [], "application/x-www-form-urlencoded",
            url_encode(Params)},
        fun(JSON) -> case json_parse(JSON) of
                {error, _, _} = Error -> Error;
                Hash -> case get_value(<<"error">>, Hash, undefined) of
                        undefined -> {ok, get_profile_info(Network, [
                            {network, NetName},
                            {access_token, get_value(<<"access_token">>, Hash)},
                            {token_type, get_value(<<"token_type">>, Hash, <<"bearer">>)}
                        ])};
                        Error -> {error, unsuccessful, Error}
                    end
            end
        end).

url_encode(Data) -> url_encode(Data,"").
url_encode([],Acc) -> list_to_binary(Acc);
url_encode([{Key,Value}|R],"") ->
    url_encode(R, edoc_lib:escape_uri(atom_to_list(Key)) ++ "=" ++
        edoc_lib:escape_uri(binary_to_list(Value)));
url_encode([{Key,Value}|R],Acc) ->
    url_encode(R, Acc ++ "&" ++ edoc_lib:escape_uri(atom_to_list(Key)) ++ "=" ++
        edoc_lib:escape_uri(binary_to_list(Value))).

gather_url_get({Path, QueryString}) ->
    iolist_to_binary([Path,
        case lists:flatten([
            ["&", edoc_lib:escape_uri(atom_to_list(K)), "=", edoc_lib:escape_uri(binary_to_list(V))]
            || {K, V} <- QueryString
        ]) of [] -> []; [_ | QS] -> [$? | QS] end]).

get_profile_info(Network, Auth) ->
    http_request_json(get, {binary_to_list(gather_url_get(
                    {get_value(userinfo_uri, Network),
                        case get_value(userinfo_composer, Network) of
                            undefined -> lists:map(fun({K, access_token}) ->
                                            {K, get_value(access_token, Auth)};
                                        (P) -> P end, get_value(userinfo_params, Network));
                            UIComp -> UIComp(Auth, Network)
                        end})), []},
            fun(JSON) -> case json_parse(JSON) of
                {error, _, _} = Error -> Error;
                Profile -> Profile1 = case get_value(field_pre, Network) of
                        undefined -> Profile; F -> F(Profile) end,
                    [{Field, case {get_value(field_fix, Network), fun(Na, Pro) ->
                                  get_value(list_to_binary(atom_to_list(Na)), Pro) end} of
                                {undefined, DefF} -> DefF(Name, Profile1);
                                {Func, DefF} -> Func(Name, Profile1, DefF)
                            end}
                        || {Field, Name} <- lists:zip([id, email, name, picture, gender, locale],
                        get_value(field_names, Network))] ++ [{raw, Profile} | Auth]
            end
        end).

predefined_networks() ->
    [
        {<<"google">>, [ % https://code.google.com/apis/console/b/0/
                {callback_uri, <<"/auth/google/callback">>},
                {scope, << "https://www.googleapis.com/auth/userinfo.email ",
                    "https://www.googleapis.com/auth/userinfo.profile" >>},
                {authorize_uri, <<"https://accounts.google.com/o/oauth2/auth">>},
                {token_uri, <<"https://accounts.google.com/o/oauth2/token">>},
                {userinfo_uri, <<"https://www.googleapis.com/oauth2/v1/userinfo">>},
                {userinfo_params, [{access_token, access_token}]},
                {field_names, [id, email, name, picture, gender, locale]}
            ]},
        {<<"facebook">>, [ % https://developers.facebook.com/apps/
                {callback_uri, <<"/auth/facebook/callback">>},
                {scope, <<"email">>},
                {authorize_uri, <<"https://www.facebook.com/dialog/oauth">>},
                {token_uri, <<"https://graph.facebook.com/oauth/access_token">>},
                {userinfo_uri, <<"https://graph.facebook.com/me">>},
                {userinfo_params, [{access_token, access_token},
                        {fields, <<"id,email,name,picture,gender,locale">>}]},
                {field_names, [id, email, name, picture, gender, locale]},
                {field_fix, fun(picture, Profile, _) ->
                            get_value(<<"url">>,
                                get_value(<<"data">>,
                                    get_value(<<"picture">>, Profile)));
                        (Other, Profile, Default) -> Default(Other, Profile) end}
            ]},
        {<<"yandex">>, [ % https://oauth.yandex.ru/client/new
                {callback_uri, <<"/auth/yandex/callback">>},
                {scope, <<>>},
                {authorize_uri, <<"https://oauth.yandex.ru/authorize">>},
                {token_uri, <<"https://oauth.yandex.ru/token">>},
                {userinfo_uri, <<"https://login.yandex.ru/info">>},
                {userinfo_params, [{oauth_token, access_token}, {format, <<"json">>}]},
                {field_names, [id, default_email, real_name, picture, sex, undefined]}
            ]},
        {<<"vkontakte">>, [ % http://vk.com/dev
                {callback_uri, <<"/auth/vkontakte/callback">>},
                {scope, <<"uid,first_name,last_name,sex,photo">>},
                {authorize_uri, <<"https://oauth.vk.com/authorize">>},
                {token_uri, <<"https://oauth.vk.com/access_token">>},
                {userinfo_uri, <<"https://api.vk.com/method/users.get">>},
                {userinfo_params, [{access_token, access_token},
                        {fields, <<"uid,first_name,last_name,sex,photo">>}]},
                {field_names, [uid, undefined, name, photo, gender, undefined]},
                {field_pre, fun(Profile) -> hd(get_value(<<"response">>, Profile)) end},
                {field_fix, fun(name, Profile, _) ->
                                    << (get_value(<<"first_name">>, Profile))/binary,
                                        " ",
                                        (get_value(<<"last_name">>, Profile))/binary >>;
                                (gender, Profile, _) -> case get_value(<<"sex">>, Profile) of
                                        1 -> <<"female">>; _ -> <<"male">> end;
                                (Other, Profile, Default) -> Default(Other, Profile) end}
            ]},
        {<<"mailru">>, [
                {callback_uri, <<"/auth/mailru/callback">>},
                {scope, <<>>},
                {authorize_uri, <<"https://connect.mail.ru/oauth/authorize">>},
                {token_uri, <<"https://connect.mail.ru/oauth/token">>},
                {userinfo_uri, <<"http://www.appsmail.ru/platform/api">>},
                {userinfo_composer, fun(Auth, Network) -> 
                           [
                                {app_id, get_value(client_id, Network)},
                                {method, <<"users.getInfo">>},
                                {secure, <<"1">>},
                                {session_key, get_value(access_token, Auth)},
                                {sig, list_to_binary(lists:flatten(
                                 [io_lib:format("~2.16.0b", [X]) || X <- binary_to_list(erlang:md5(
                                      <<"app_id=", (get_value(client_id, Network))/binary,
                                        "method=users.getInfosecure=1session_key=",
                                        (get_value(access_token, Auth))/binary,
                                        (get_value(client_secret_key, Network))/binary>>
                                    ))]))}
                            ] end},
                {field_names, [uid, email, name, pic, sex, undefined]},
                {field_pre, fun(Profile) -> hd(Profile) end},
                {field_fix, fun(name, Profile, _) ->
                                    << (get_value(<<"first_name">>, Profile))/binary,
                                        " ",
                                        (get_value(<<"last_name">>, Profile))/binary >>;
                                (sex, Profile, _) -> case get_value(<<"sex">>, Profile) of
                                        1 -> <<"female">>; _ -> <<"male">> end;
                                (Other, Profile, Default) -> Default(Other, Profile) end}

            ]},
        {<<"paypal">>, [
                {callback_uri, <<"/auth/paypal/callback">>},
                {scope, <<"https://identity.x.com/xidentity/resources/profile/me">>},
                {authorize_uri, <<"https://identity.x.com/xidentity/resources/authorize">>},
                {token_uri, <<"https://identity.x.com/xidentity/oauthtokenservice">>}
            ]},
        {<<"github">>, [
                {callback_uri, <<"/auth/github/callback">>},
                {scope, <<>>},
                {authorize_uri, <<"https://github.com/login/oauth/authorize">>},
                {token_uri, <<"https://github.com/login/oauth/access_token">>}
            ]}
    ].