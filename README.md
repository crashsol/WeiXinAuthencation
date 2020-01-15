# 本文参考了 QQConnect
asp.net core2.0 QQ登录、微信登录

基于Microsoft.AspNetCore.Authentication.OAuth实现([aspnet/Security2.0](https://github.com/aspnet/Security/tree/rel/2.0.0))

[QQ Connect接入文档](http://wiki.connect.qq.com/%E5%87%86%E5%A4%87%E5%B7%A5%E4%BD%9C_oauth2-0)

[微信开方平台](https://open.weixin.qq.com/) 网站微信登录在这里申请  

特别提醒，网站要接入微信登录（具体有两种情况：1.在微信客户端外浏览网站打开微信登录时是先显示一个二维码，用户使用微信客户端扫码后在微信客户端内会显示一个授权界面，用户授权后，网站会自动跳转到你设置的回调地址。2.在微信内浏览网站时用户微信登录，当用户点了微信登录后会直接转到授权界面，用户授权后，网站会自动跳转到你设置的回调地址）是在开放平台申请，必须要开通开发者资质，也就是说300RMB是必须的，不然创建的网站应用通过后也无法使用（可以先创建应用再申请资质，只不过开发者资质下来之前没法用）。  

很多人不知道跑到微信公众平台申请测试帐号，告诉你没用的，网站应用使用微信登录只能在开放平台申请，而且在开发者资质下来之前测试都没法测试。那些跑去申请微信公众平台测试帐号的大概是被网上有些文章给误导了，微信公众平台的确有提供微信登录的接口，但是，此登录非彼登录，它这个只适用于在**微信服务号内嵌网站**使用的微信登录，只有服务号才有，订阅号是没有的。  

总结一句话就是：微信开放平台和微信公众平台都有提供网站用微信登录的接口，前者适用于任何网站，后者只适用于微信服务号的内嵌网站。

****
## 使用方法

### 微信

~~~
//appsettings.json
{
    "Authentication": {
      "WeChat": {
            "AppId": "你申请的微信应用AppID",
            "AppSecret": "你申请的微信应用AppSecret"
        }
    },
    //省略....
}
~~~
~~~
//Startup.cs
services.AddAuthentication().AddWeChat(wechatOptions => {
    wechatOptions.AppId = Configuration["Authentication:WeChat:AppId"];
    wechatOptions.AppSecret = Configuration["Authentication:WeChat:AppSecret"];
}) ;
~~~
### 注意如果你有多个后端服务器，需要使用真实的分布式缓存
~~~
 services.AddAuthentication()
                .AddWeChat(wechatOptions => {
                    wechatOptions.AppId = configuration["Authentication:WeChat:AppId"];
                    wechatOptions.AppSecret = configuration["Authentication:WeChat:AppSecret"];
                    //启用使用分布式缓存，一般不需要设定
                    wechatOptions.UseCachedStateDataFormat = true;
                })
 services.AddDistributedMemoryCache();
~~~
