// See https://aka.ms/new-console-template for more information
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

Console.WriteLine("Active directory token validation against specific app!");
string token = "";
string myTenant = "";
string myappid = "";  //app id allow to access the azure resource
var myIssuer = String.Format(CultureInfo.InvariantCulture, "https://sts.windows.net/", myTenant);
var stsDiscoveryEndpoint = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration";
var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint, new OpenIdConnectConfigurationRetriever());

var config = await configManager.GetConfigurationAsync();

var tokenHandler = new JwtSecurityTokenHandler();

if (token.IndexOf("Bearer") >= 0)
    token = token.Replace("Bearer", "");

var validationParameters = new TokenValidationParameters
{
    ValidateAudience = false,
    ValidateIssuer = true,
    ValidIssuer = myIssuer,
    IssuerSigningKeys = config.SigningKeys,
    ValidateLifetime = false
};

var handler = new JwtSecurityTokenHandler();
SecurityToken jwt;
var result = handler.ValidateToken(token, validationParameters, out jwt);

if (result != null)
{
    var jwtSecurityToken = jwt as JwtSecurityToken;
    //validating the app id from the token and token is not expired
    if (jwtSecurityToken.Claims.Where(x => x.Type == "appid").FirstOrDefault().Value != myappid || jwtSecurityToken.ValidTo < DateTime.UtcNow)
    {
        Console.WriteLine("Http 401: Unauthorized Access");
    }
}

Console.ReadLine();
