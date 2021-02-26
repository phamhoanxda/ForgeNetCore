using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Autodesk.Forge;

namespace AutodeskForgeTTD.Controllers
{
    [ApiController]
    public class OAuthController : ControllerBase
    {  
        // As both internal & public tokens are used for all visitors
        // we don't need to request a new token on every request, so let's
        // cache them using static variables. Note we still need to refresh
        // them after the expires_in time (in seconds)

        private static dynamic InternalToken { get; set;}
        private static dynamic PublicToken { get; set; }

        /// <summary>
        /// Get access token with public (viewables:read) scope
        /// </summary>
        /// 

        [HttpGet]
        [Route("api/forge/oauth/token")]
        public async Task<dynamic> GetPublicAsync()
        {
            if(PublicToken == null || PublicToken.ExpiresAt < DateTime.UtcNow)
            {
                PublicToken = await Get2LeggedTokenAsync(new Scope[] { Scope.ViewablesRead });
                PublicToken.ExpiresAt = DateTime.UtcNow.AddSeconds(PublicToken.expires_in);
            }
            return PublicToken;
        }

        public static async Task<dynamic> GetInternalAsync()
        {
            if(InternalToken == null || InternalToken.ExpiresAt < DateTime.UtcNow)
            {
                InternalToken = await Get2LeggedTokenAsync(new Scope[] { Scope.BucketCreate, Scope.BucketRead, Scope.BucketDelete, Scope.DataRead, Scope.DataCreate, Scope.DataWrite, Scope.CodeAll });
                InternalToken.ExpireAt = DateTime.UtcNow.AddSeconds(InternalToken.expires_in);
            }
            return InternalToken;

        }

        private static string clientId = "FORGE_CLIENT_ID";
        private static string secret = "FORGE_CLIENT_SECRET";


        private static async Task<dynamic> Get2LeggedTokenAsync (Scope[] scopes)
        {
            TwoLeggedApi oauth = new TwoLeggedApi();
            string grantType = "client_cridentials";
            dynamic bearer = await oauth.AuthenticateAsync(GetAppSetting(clientId), GetAppSetting(secret), grantType, scopes);
            return bearer;

        }

        public static string GetAppSetting(string settingKey)
        {
            return Environment.GetEnvironmentVariable(settingKey).Trim();
        }
    }
}
