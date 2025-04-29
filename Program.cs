using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using JWT;
using JWT.Algorithms;
using JWT.Builder;
using static Program;
using System.Reflection;

class Program
{
    private static readonly string providerName = ""; // Get From Admins
    private static readonly string providerSalt = ""; // Get From Admins
    private static readonly string auth = "voided-";  // Get From Auth Page

    private static readonly string ENDPOINT = "https://voided.to/auth.php";
    private static readonly Dictionary<string, string> HEADERS = new Dictionary<string, string>
    {
        { "PKey", "" },
        { "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" },
        { "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" },
        { "Accept-Language", "en-US,en;q=0.5" },
        { "Connection", "keep-alive" },
        { "Referer", "https://voided.to/" }
    };

    static async Task Main(string[] args)
    {
        List<string> requiredRankMinimum = new List<string> { "vip", "exclusive", "cosmo" };

        List<string> requiredRankIndex = new List<string>();
        bool authed = false;

        var result = await Auth.Main();
        if (result.ContainsKey("username"))
        {
            string username = result["username"].ToString();
            string groups = result["usergroup"].ToString();


            foreach (KeyValuePair<string, string> rank in Ranks.RankDict)
            {
                string id = rank.Key;
                string title = rank.Value.ToLower();
                foreach (string allowedRanks in requiredRankMinimum)
                {
                    if (allowedRanks.ToLower() == title)
                    {
                        requiredRankIndex.Add(id);
                        break;
                    }

                }
  
            }
            
            string[] userGroups = groups.Split(',');
            foreach (string rankIndex in requiredRankIndex)
            {
                if (userGroups.Contains(rankIndex))
                {
                    Console.WriteLine("USER AUTHED");
                    authed = true;
                    break;
                }
            }

            if (!authed)
            {
                Console.WriteLine("Rank is too low");
            }
        }
        else
        {
            string Jobject = JsonConvert.SerializeObject(result);
            dynamic dynamicObject = JsonConvert.DeserializeObject(Jobject);
            Console.WriteLine(dynamicObject.error);
        }
    }

    public static class Functions
    {
        public static string GeneratePkey(string providerName, string providerSalt)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] providerNameBytes = Encoding.UTF8.GetBytes(providerName);
                byte[] providerNameHash = sha256.ComputeHash(providerNameBytes);
                string providerNameHashHex = BitConverter.ToString(providerNameHash).Replace("-", "").ToLower();

                string combinedString = providerSalt + providerNameHashHex;
                byte[] combinedBytes = Encoding.UTF8.GetBytes(combinedString);
                byte[] finalHash = sha256.ComputeHash(combinedBytes);
                return BitConverter.ToString(finalHash).Replace("-", "").ToLower();
            }
        }

        public static Dictionary<string, object> DecodeJwt(string token, bool verify = false, string secret = null, string[] algorithms = null, Dictionary<string, object> options = null)
        {
            if (string.IsNullOrEmpty(token))
            {
                throw new Exception("No JWT token available");
            }

            if (options == null)
            {
                options = new Dictionary<string, object> { { "verify_signature", verify } };
            }

            if (verify && string.IsNullOrEmpty(secret))
            {
                throw new Exception("Secret key required for JWT verification");
            }

            try
            {
                if (verify)
                {
                    var payload = JwtBuilder.Create()
                        .WithAlgorithm(new HMACSHA256Algorithm())
                        .WithSecret(secret)
                        .MustVerifySignature()
                        .Decode<Dictionary<string, object>>(token);
                    return payload;
                }
                else
                {
                    var payload = JwtBuilder.Create()
                        .DoNotVerifySignature()
                        .Decode<Dictionary<string, object>>(token);
                    return payload;
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to decode JWT: {ex.Message}");
            }
        }
    }

    public static class Ranks
    {
        public static readonly Dictionary<string, string> RankDict = new Dictionary<string, string>
    {
        { "1", "Guests" },
        { "2", "Registered" },
        { "3", "Headstaff" },
        { "4", "Administrators" },
        { "5", "Awaiting Activation" },
        { "6", "Staff" },
        { "7", "Banned" },
        { "8", "Contributor" },
        { "9", "Respected" },
        { "10", "Veteran" },
        { "11", "Vip" },
        { "12", "Exclusive" },
        { "13", "Cosmo" },
        { "14", "Developers" },
        { "15", "Banned for Leeching" },
        { "16", "Disinfector" },
        { "21", "Bot" },
        { "22", "Coder" }
    };
    }

    public static class Auth
    {
        public static async Task<Dictionary<string, object>> Main()
        {
            string pkey = Functions.GeneratePkey(providerName, providerSalt);
            HEADERS["PKey"] = pkey;

            using (HttpClient client = new HttpClient())
            {
                foreach (var header in HEADERS)
                {
                    client.DefaultRequestHeaders.Add(header.Key, header.Value);
                }

                string requestUrl = $"{ENDPOINT}?action=v2&key={auth}&provider={providerName}";
                HttpResponseMessage response = await client.GetAsync(requestUrl);
                string responseContent = await response.Content.ReadAsStringAsync();

                if (responseContent.Contains("success"))
                {
                    JObject jsonResponse = JObject.Parse(responseContent);
                    string jwt = jsonResponse["jwt"].ToString();
                    return Functions.DecodeJwt(jwt);
                }
                else
                {
                    JObject jsonResponse = JObject.Parse(responseContent);
                    return new Dictionary<string, object> { { "error", jsonResponse["error"].ToString() } };
                }
            }
        }
    }
}