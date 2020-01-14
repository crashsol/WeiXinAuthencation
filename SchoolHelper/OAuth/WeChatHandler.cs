using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Text.Json;

namespace Microsoft.AspNetCore.Authentication.WeChat
{
    internal class WeChatHandler : OAuthHandler<WeChatOptions>
    {

        private readonly ISecureDataFormat<AuthenticationProperties> _secureDataFormat;


        private const string OauthState = "_oauthstate";
        private const string State = "state";

        /// <summary>
        /// Called after options/events have been initialized for the handler to finish initializing itself.
        /// </summary>
        /// <returns>A task</returns>
        protected override async Task InitializeHandlerAsync()
        {
            await base.InitializeHandlerAsync();
            if (Options.UseCachedStateDataFormat)
            {
                Options.StateDataFormat = _secureDataFormat;
            }       
        }

        public WeChatHandler(
             IOptionsMonitor<WeChatOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            ISecureDataFormat<AuthenticationProperties> secureDataFormat)
            : base(options, logger, encoder, clock)
        {
            _secureDataFormat = secureDataFormat;
        }
        /*
         * Challenge 盘问握手认证协议
         * 这个词有点偏，好多翻译工具都查不出。
         * 这个解释才是有些靠谱 http://abbr.dict.cn/Challenge/CHAP
         */
        /// <summary>
        /// 构建请求CODE的Url地址（这是第一步，准备工作）
        /// </summary>
        /// <param name="properties"></param>
        /// <param name="redirectUri"></param>
        /// <returns></returns>
        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            {
                string stateValue = Options.StateDataFormat.Protect(properties);
                bool addRedirectHash = false;

                if (!IsWeixinAuthorizationEndpointInUse())
                {
                    //Store state in redirectUri when authorizing Wechat Web pages to prevent "too long state parameters" error
                    redirectUri = QueryHelpers.AddQueryString(redirectUri, OauthState, stateValue);
                    addRedirectHash = true;
                }

                var isMicroMessenger = Options.IsWeChatBrowser(Request);
                var remoteUrl = isMicroMessenger ? Options.AuthorizationInWeiXinBrowerEndpoint
                        : Options.AuthorizationEndpoint;
                redirectUri = QueryHelpers.AddQueryString(remoteUrl, new Dictionary<string, string>
                {
                    ["appid"] = Options.ClientId,
                    ["scope"] = FormatScope(),
                    ["response_type"] = "code",
                    ["redirect_uri"] = redirectUri,
                    [State] = addRedirectHash ? OauthState : stateValue
                });

                if (addRedirectHash)
                {
                    // The parameters necessary for Web Authorization of Wechat
                    redirectUri += "#wechat_redirect";
                }
                return redirectUri;
            }
            {
                var scope = FormatScope();
                var state = Options.StateDataFormat.Protect(properties);
                var parameters = new Dictionary<string, string>()
            {
                { "appid", Options.ClientId },
                { "redirect_uri", redirectUri },
                { "response_type", "code" },
                //{ "scope", scope },
                //{ "state", state },
            };
                //判断当前请求是否由微信内置浏览器发出
                var isMicroMessenger = Options.IsWeChatBrowser(Request);
                var ret = QueryHelpers.AddQueryString(
                   , parameters);

                //scope 不能被UrlEncode
                ret += $"&scope={scope}&state={state}";
                return ret;
            }
        }

        /// <summary>
        /// 处理微信授权结果（接收微信授权的回调）
        /// </summary>
        /// <returns></returns>
        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            //第一步，处理工作
            AuthenticationProperties properties = null;
            var query = Request.Query;
            //微信只会发送code和state两个参数，不会返回错误消息
            //若用户禁止授权，则重定向后不会带上code参数，仅会带上state参数
            var code = query["code"];
            var state = query["state"];
            properties = Options.StateDataFormat.Unprotect(state);
            if (properties == null)
            {
                return HandleRequestResult.Fail("The oauth state was missing or invalid.");
            }
            // OAuth2 10.12 CSRF
            if (!ValidateCorrelationId(properties))
            {
                return HandleRequestResult.Fail("Correlation failed.");
            }
            if (StringValues.IsNullOrEmpty(code)) //code为null就是
            {
                return HandleRequestResult.Fail("Code was not found.");
            }

            //第二步，通过Code获取Access Token
            var tokens = await ExchangeCodeAsync(new OAuthCodeExchangeContext(properties,code,""));
            if (tokens.Error != null)
            {
                return HandleRequestResult.Fail(tokens.Error);
            }
            if (string.IsNullOrEmpty(tokens.AccessToken))
            {
                return HandleRequestResult.Fail("Failed to retrieve access token.");
            }
            var identity = new ClaimsIdentity(ClaimsIssuer);
            if (Options.SaveTokens)
            {
                var authTokens = new List<AuthenticationToken>();
                authTokens.Add(new AuthenticationToken { Name = "access_token", Value = tokens.AccessToken });
                if (!string.IsNullOrEmpty(tokens.RefreshToken))
                {
                    authTokens.Add(new AuthenticationToken { Name = "refresh_token", Value = tokens.RefreshToken });
                }
                if (!string.IsNullOrEmpty(tokens.TokenType)) //微信就没有这个
                {
                    authTokens.Add(new AuthenticationToken { Name = "token_type", Value = tokens.TokenType });
                }
                if (!string.IsNullOrEmpty(tokens.ExpiresIn))
                {
                    int value;
                    if (int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
                    {                       
                        var expiresAt = Clock.UtcNow + TimeSpan.FromSeconds(value);
                        authTokens.Add(new AuthenticationToken
                        {
                            Name = "expires_at",
                            Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                        });
                    }
                }

                properties.StoreTokens(authTokens);
            }

            var ticket = await CreateTicketAsync(identity, properties, tokens);
            if (ticket != null)
            {
                return HandleRequestResult.Success(ticket);
            }
            else
            {
                return HandleRequestResult.Fail("Failed to retrieve user information from remote server.");
            }
        }

        /// <summary>
        /// 通过Code获取Access Token(这是第二步) 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(OAuthCodeExchangeContext context)
        {
            string address = QueryHelpers.AddQueryString(Options.TokenEndpoint, new Dictionary<string, string>()
            {
                ["appid"] = Options.ClientId,
                ["secret"] = Options.ClientSecret,
                ["code"] = context.Code,
                ["grant_type"] = "authorization_code"
            });
            using var response = await Backchannel.GetAsync(address, Context.RequestAborted);
            var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            if (!string.IsNullOrEmpty(payload.RootElement.GetString("errcode")))
            {
                Logger.LogError("An error occurred while retrieving an access token: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                return OAuthTokenResponse.Failed(new Exception("An error occurred while retrieving an access token."));
            }
            return OAuthTokenResponse.Success(payload);            
        }      
       

        /// <summary>
        /// 创建身份票据(这是第三步) 
        /// </summary>
        /// <param name="identity"></param>
        /// <param name="properties"></param>
        /// <param name="tokens"></param>
        /// <returns></returns>
        protected override async Task<AuthenticationTicket> CreateTicketAsync(
            ClaimsIdentity identity,
            AuthenticationProperties properties,
            OAuthTokenResponse tokens)
        {

            string address = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, new Dictionary<string, string>
            {
                ["access_token"] = tokens.AccessToken,
                ["openid"] = tokens.Response.RootElement.GetString("openid")
            });

            using var response = await Backchannel.GetAsync(address);
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving user information.");
            }

            using var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            if (!string.IsNullOrEmpty(payload.RootElement.GetString("errcode")))
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving user information.");
            }

            var principal = new ClaimsPrincipal(identity);
            var context = new OAuthCreatingTicketContext(principal, properties, Context, Scheme, Options, Backchannel, tokens, payload.RootElement);
            context.RunClaimActions();

            await Options.Events.CreatingTicket(context);
            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);           
        }

        private static string GetOpenId(JsonDocument json)
        {
            return json.RootElement.GetString("openid");
        }
        private static string GetUnionId(JsonDocument json)
        {
            return json.RootElement.GetString("unionid");
        }

        /// <summary>
        /// 根据是否为微信浏览器返回不同Scope
        /// </summary>
        /// <returns></returns>
        protected override string FormatScope()
        {
            if (Options.IsWeChatBrowser(Request))
            {
                return string.Join(",", Options.Scope2);
            }
            else
            {
                return string.Join(",", Options.Scope);
            }
            
        }

        private bool IsWeixinAuthorizationEndpointInUse()
        {
            return string.Equals(Options.AuthorizationEndpoint, WeixinAuthenticationDefaults.AuthorizationEndpoint, StringComparison.OrdinalIgnoreCase);
        }



    }
}
