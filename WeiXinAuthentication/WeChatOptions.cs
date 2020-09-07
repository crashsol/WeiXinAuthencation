using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using System.Linq;
using System.Security.Claims;
using Microsoft.Net.Http.Headers;
namespace Microsoft.AspNetCore.Authentication.WeChat
{
    public class WeChatOptions : OAuthOptions
    {

        public static string UserInfoScope = "snsapi_userinfo";
        public static string LoginScope = "snsapi_login";

        public WeChatOptions()
        {
            CallbackPath = new PathString("/signin-wechat");
            AuthorizationEndpoint = WeChatDefaults.AuthorizationEndpoint;
            AuthorizationInWeiXinBrowerEndpoint = WeChatDefaults.AuthorizationInWeiXinBrowerEndpoint;
            TokenEndpoint = WeChatDefaults.TokenEndpoint;
            UserInformationEndpoint = WeChatDefaults.UserInformationEndpoint;

            //Scope 表示应用授权作用域。
            //网页上登录（非微信浏览器）需要两个Scope，一个是UserInfo，一个是Login
            Scope.Add(UserInfoScope);
            Scope.Add(LoginScope);

            //微信内嵌浏览器Login只需要UserInfo
            Scope2 = new List<string>();
            Scope2.Add(UserInfoScope);

            //除了openid外，其余的都可能为空，因为微信获取用户信息是有单独权限的
            ClaimActions.MapJsonKey("urn:wechat:openid", "openid");
            ClaimActions.MapJsonKey("urn:wechat:nickname", "nickname");
            ClaimActions.MapJsonKey("urn:wechat:sex", "sex",ClaimValueTypes.Integer);
            ClaimActions.MapJsonKey("urn:wechat:country", "country");//ClaimTypes.Locality
            ClaimActions.MapJsonKey("urn:wechat:province", "province");//ClaimTypes.StateOrProvince
            ClaimActions.MapJsonKey("urn:wechat:city", "city");//ClaimTypes.StreetAddress
            ClaimActions.MapJsonKey("urn:wechat:headimgurl", "headimgurl");
            ClaimActions.MapJsonKey("urn:wechat:unionid", "unionid");
            ClaimActions.MapCustomJson("urn:wechat:privilege", user =>
            {
                if (!user.TryGetProperty("privilege", out var value) || value.ValueKind != System.Text.Json.JsonValueKind.Array)
                {
                    return null;
                }
                return string.Join(",", value.EnumerateArray().Select(element => element.GetString()));
            });   

            IsWeChatBrowser=(r) => r.Headers[HeaderNames.UserAgent].ToString().ToLower().Contains("micromessenger");
        }


        /// <summary>
        /// 应用唯一标识，在微信开放平台提交应用审核通过后获得
        /// </summary>
        public string AppId
        {
            get { return ClientId; }
            set { ClientId = value; }
        }
        /// <summary>
        /// 应用密钥AppSecret，在微信开放平台提交应用审核通过后获得
        /// </summary>
        public string AppSecret
        {
            get { return ClientSecret; }
            set { ClientSecret = value; }
        }

        /// <summary>
        /// 网站微信登录有两种场景，一种是在微信客户端内打开登录，一种是在微信客户端外登录。
        /// 在微信内登录直接转到让用户授权页面，在微信外则为显示二微码让用户扫描后在微信内授权。
        /// AuthorizationEndpoint是在微信外登录地址，AuthorizationInWeiXinBrowerEndpoint是微信内登录地址
        /// </summary>
        public string AuthorizationInWeiXinBrowerEndpoint { get; set; }

        /// <summary>
        /// 微信内登录地址 的Scope
        /// </summary>
        public ICollection<string> Scope2 { get; set; }

        /// <summary>
        /// 是否是微信内置浏览器
        /// </summary>
        public Func<HttpRequest, bool> IsWeChatBrowser { get; set; }

        public bool UseCachedStateDataFormat { get; set; } = false;

    }
}
