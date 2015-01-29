-module(simple_oauth2_server_profiles).
-export([configured_networks/0]).
-export([google/0, facebook/0, yandex/0, vkontakte/0, mailru/0, paypal/0, github/0]).

configured_networks() ->
    {ok, Networks} = application:get_env(simple_oauth2, networks),
    [config_network(N) || N <- Networks].

config_network({NetName, Settings}) when is_list(Settings) ->
    Predefined = erlang:apply(simple_oauth2_server_profiles, NetName, []),
    {NetName, merge(Predefined, Settings)}. 

merge(KeyListBase, []) -> KeyListBase;
merge(KeyListBase, [H = {Key, _} | T]) ->
    merge(lists:keyreplace(1, Key, KeyListBase, H), T).

-type userinfo_field() :: { atom(), binary() }.
-type userinfo() :: [ userinfo_field() ].
-type userinfo_composer() :: {userinfo_composer, fun(([tuple()], [tuple()]) -> userinfo() ) }.
-type authorize_uri() :: { authorize_uri, binary()}.
-type callback_uri() :: { callback_uri, binary()}.
-type access_token() :: { access_token, binary()}.
-type scope() :: { scope, binary() }.
-type token_uri() :: { token_uri, binary() }.
-type userinfo_uri() :: { userinfo_uri, binary() }.
-type field_pre() :: fun( ([tuple()]) -> term() ).
-type token_type() :: access_token | oauth_token.
-type userinfo_params_tuple() :: { token_type(), token_type() }.
-type userinfo_param() :: userinfo_params_tuple() | {fields, binary()} | { format, binary() }.
-type userinfo_params() :: [ userinfo_param() ].
-type field_names() :: [ atom() ].
-type field_fix() :: { field_fix, fun((atom(), [tuple()], fun((atom(), [tuple()])-> term())) -> term())}.

-type oauth_net_setting() ::    userinfo_params() | 
                                authorize_uri() | 
                                userinfo_composer() |
                                callback_uri() | 
                                access_token() | 
                                scope() | 
                                field_pre() |
                                field_fix() |
                                token_uri() |
                                field_names() | 
                                userinfo_uri().

-type oauth_net_settings() :: [ oauth_net_setting() ].

-spec configured_networks() -> [any()].
-spec config_network({atom(),[{pos_integer(),_}]}) -> any().
-spec merge(_,[{pos_integer(),_}]) -> any().


-spec google() -> oauth_net_settings().
google() -> 
	[ % https://code.google.com/apis/console/b/0/
        {callback_uri, <<"/auth/google/callback">>},
        {scope, << "https://www.googleapis.com/auth/userinfo.email ",
            "https://www.googleapis.com/auth/userinfo.profile" >>},
        {authorize_uri, <<"https://accounts.google.com/o/oauth2/auth">>},
        {token_uri, <<"https://accounts.google.com/o/oauth2/token">>},
        {userinfo_uri, <<"https://www.googleapis.com/oauth2/v1/userinfo">>},
        {userinfo_params, [{access_token, access_token}]},
        {field_names, [id, email, name, picture, gender, locale]}
    ].
facebook() ->
    [ % https://developers.facebook.com/apps/
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
    ].

yandex() ->
    [ % https://oauth.yandex.ru/client/new
        {callback_uri, <<"/auth/yandex/callback">>},
        {scope, <<>>},
        {authorize_uri, <<"https://oauth.yandex.ru/authorize">>},
        {token_uri, <<"https://oauth.yandex.ru/token">>},
        {userinfo_uri, <<"https://login.yandex.ru/info">>},
        {userinfo_params, [{oauth_token, access_token}, {format, <<"json">>}]},
        {field_names, [id, default_email, real_name, picture, sex, undefined]}
    ].

vkontakte() ->
    [ % http://vk.com/dev
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
    ].

mailru() ->
    [
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

    ].

paypal() ->
    [
        {callback_uri, <<"/auth/paypal/callback">>},
        {scope, <<"https://identity.x.com/xidentity/resources/profile/me">>},
        {authorize_uri, <<"https://identity.x.com/xidentity/resources/authorize">>},
        {token_uri, <<"https://identity.x.com/xidentity/oauthtokenservice">>}
    ].


github() ->
    [
        {callback_uri, <<"/auth/github/callback">>},
        {scope, <<>>},
        {authorize_uri, <<"https://github.com/login/oauth/authorize">>},
        {token_uri, <<"https://github.com/login/oauth/access_token">>}
    ].

get_value(Key, PList) ->
    proplists:get_value(Key, PList).