using Autodesk.Forge;
using Autodesk.Forge.Model;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace AutodeskForgeTTD.Controllers
{
    public class OSSController : ControllerBase
    {
        private IWebHostEnvironment _env;
        public OSSController(IWebHostEnvironment env) { _env = env; }
        public string ClientId { get { return OAuthController.GetAppSetting("FORGE_CLIENT_ID").ToLower(); } }

        [HttpGet]
        [Route("api/forge/oss/buckets")]
        public async Task<IList<TreeNode>>GetOSSAsync(string id)
        {
            IList<TreeNode> nodes = new List<TreeNode>();
            dynamic oauth = await OAuthController.GetInternalAsync();

            if (id == "#") //root
            {
                // in this case, let 's return all buckets
                BucketsApi appBuckets = new BucketsApi();
                appBuckets.Configuration.AccessToken = oauth.access_token;

                // to simplify, let's return only the first 100 buckets
                dynamic buckets = await appBuckets.GetBucketsAsync("US", 100);
                foreach (KeyValuePair<string, dynamic> bucket in new DynamicDictionaryItems(buckets.items))
                {
                    nodes.Add(new TreeNode(bucket.Value.bucketKey, bucket.Value.bucketKey.Replace(ClientId + "-", string.Empty), "bucket", true));
                }

            }

        }


    /// <summary>
    /// Model data for jsTree used on GetOSSAsync
    /// </summary>
    public class TreeNode
    {
        public string id { get; set; }
        public string text { get; set; }
        public string type { get; set; }
        public bool children { get; set; }

        public TreeNode(string id, string text, string type, bool children)
        {
            this.id = id;
            this.text = text;
            this.type = type;
            this.children = children;
        }
    }
}
