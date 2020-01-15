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
using System.Linq;
using Microsoft.AspNetCore.Http;

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
            //  是否使用
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

      
        /// <summary>
        /// 构建请求CODE的Url地址（这是第一步，准备工作）
        /// </summary>
        /// <param name="properties"></param>
        /// <param name="redirectUri"></param>
        /// <returns></returns>
        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {

            string stateValue = Options.StateDataFormat.Protect(properties);

            //重新生成回调地址，添加state别名,防止stateCode太长
            redirectUri = QueryHelpers.AddQueryString(redirectUri, OauthState, stateValue);
            //根据当前浏览器环境监测，是否是在微信浏览器内调用
            var isMicroMessenger = Options.IsWeChatBrowser(Request);
            var remoteUrl = isMicroMessenger ? Options.AuthorizationInWeiXinBrowerEndpoint
                    : Options.AuthorizationEndpoint;
            redirectUri = QueryHelpers.AddQueryString(remoteUrl, new Dictionary<string, string>
            {
                ["appid"] = Options.ClientId,
                ["scope"] = FormatScope(),
                ["response_type"] = "code",
                ["redirect_uri"] = redirectUri,
                [State] =  OauthState 
            });        
            // 如果在微信外面登录，需要添加#wechat_redirect 参数
            if (isMicroMessenger == false)
            {
                redirectUri += "#wechat_redirect";
            }
            return redirectUri;
        }

        /// <summary>
        /// 处理微信授权结果（接收微信授权的回调）
        /// </summary>
        /// <returns></returns>
        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            //将oauthState赋值给state
            if (Request.Query.TryGetValue(OauthState, out var stateValue))
            {
                var query = Request.Query.ToDictionary(c => c.Key, c => c.Value, StringComparer.OrdinalIgnoreCase);
                if (query.TryGetValue(State, out var _))
                {
                    query[State] = stateValue;
                    Request.QueryString = QueryString.Create(query);
                }
            }
            return await base.HandleRemoteAuthenticateAsync();
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


    }
}
