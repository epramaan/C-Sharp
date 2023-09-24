using System;
using System.Web.Mvc;
using System.Text;
using System.Security.Cryptography;
using IdentityModel;
using RestSharp;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace OIDC_DOT_NET_INTEGRATION_PRODUCTION.Controllers
{
    public class EpramaanController : Controller
    {
        public static readonly string scope = "openid";
        public static readonly string response_type = "code";
        public static readonly string code_challenge_method = "S256";
        public static readonly string grant_type = "authorization_code";

        public static readonly string auth_grant_request_uri = "https://epramaan.meripehchaan.gov.in/openid/jwt/processJwtAuthGrantRequest.do";
        public static readonly string token_request_uri = "https://epramaan.meripehchaan.gov.in/openid/jwt/processJwtTokenRequest.do";
        public static readonly string push_back_uri = "https://epramaan.meripehchaan.gov.in/rest/epramaan/enrol/response";

        public static readonly string client_id = "1*********1231";
        public static readonly string salt = "1****1";
        public static readonly string aeskey = "c*********************b3";
        public static readonly string redirect_uri = "http://localhost:44355/Epramaan/ProcessAuthCodeAndGetToken";
        public static readonly string Certificate = "D:/Integration/aspDotNet/OidcDotNetProduction/OidcDotNetProduction/epramaanprod2016.cer";

        public static string codeVerifier;
        public static string stateID;
        public static string nonce;

        public ActionResult LoginUsingEpramaan()
        {
            stateID = Guid.NewGuid().ToString();                //Must be unique and create new for each request
            nonce = CryptoRandom.CreateUniqueId(16);            //Create new randomly generated 16 characters string for every request
            codeVerifier = CryptoRandom.CreateUniqueId(64);     //Create new randomly generated 64 characters string for every request

            //Create new Code Challenge with the code Verifier for every request
            string code_challenge;
            using (var sha256 = SHA256.Create())
            {
                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                code_challenge = IdentityModel.Base64Url.Encode(challengeBytes);
            }

            string inputvalue = client_id + aeskey + stateID + nonce + redirect_uri + scope + code_challenge;

            //HMAC SHA256 of queryString 
            string apiHmac = hashHMACHex(inputvalue, aeskey);
            ViewBag.finalUrl = auth_grant_request_uri + "?&scope=" + scope + "&response_type=" + response_type + "&redirect_uri=" + redirect_uri + "&state=" + stateID + "&code_challenge_method=" + code_challenge_method + "&nonce=" + nonce + "&client_id=" + client_id + "&code_challenge=" + code_challenge + "&request_uri=" + auth_grant_request_uri + "&apiHmac=" + apiHmac;
            return View();
        }

        [HttpPost]
        public ActionResult OneTimeVerificationForUser(string ssoToken)
        {
            ViewBag.ssoToken = ssoToken;
            string decryptedText = Decrypt(ssoToken, aeskey); //for first time OTV this is JWT token
            int saltIndex = decryptedText.LastIndexOf(salt);
            if (saltIndex != -1)
            {
                decryptedText = decryptedText.Substring(0, saltIndex);
            }
            string ssoId = JObject.Parse(decryptedText)["sso_id"].ToString(); //Install NuGet Package Newtonsoft.Json
            ViewBag.epramaanId = ssoId;
            ViewBag.salt = salt;
            return View();
        }

        [HttpPost]
        public ActionResult OneTimePushBack(string username, string password, string epramaanId, string salt)
        {
            string transactionId = epramaanId;
            DateTimeOffset currentTime = DateTimeOffset.Now;
            long responseTimestamp = currentTime.ToUnixTimeMilliseconds();
            int serviceId = int.Parse(client_id);
            string serviceUserId = username;
            Boolean verified = true;

            if (!(username == "cdac" && password == "cdac"))
            {
                verified = false;
                serviceUserId = "";
            }

            var pushBackObj = new Dictionary<string, object>
            {
                { "transactionId", transactionId },
                { "responseTimestamp", responseTimestamp },
                { "serviceId", serviceId },
                { "serviceUserId", serviceUserId },
                { "verified", verified }
            };

            // Serialize the dictionary to JSON
            string plainTextEnrolSPServiceResponse = JsonConvert.SerializeObject(pushBackObj) + salt;
            string encryptedEnrolSPServiceResponse = Encrypt(plainTextEnrolSPServiceResponse, aeskey);

            var jsonVariables = new Dictionary<string, object>
            {
                { "serviceId", client_id },
                { "encryptedEnrolSPServiceResponse", encryptedEnrolSPServiceResponse }
            };
            string EnrolSPServiceResponseWrapper = JsonConvert.SerializeObject(jsonVariables);

            var client = new RestClient(push_back_uri);         //install NuGet package "RestSharp", version must be <=106.0.0
            var request = new RestSharp.RestRequest(Method.POST);
            request.AddHeader("Content-Type", "application/json");
            var body = EnrolSPServiceResponseWrapper;
            request.AddParameter("application/json", body, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);
            string responseString = response.Content;
            ViewBag.responseString = responseString;
            return View();
        }

        [HttpPost]
        public ActionResult ProcessAuthCodeAndGetToken(string code, string state)
        {
            string authCode = code;
            var client = new RestClient(token_request_uri);         //install NuGet package "RestSharp", version must be <=106.0.0
            var request = new RestSharp.RestRequest(Method.POST);
            request.AddHeader("Content-Type", "application/json");
            var body = "{\"code\":[\"" + authCode + "\"],\"grant_type\":[\"" + grant_type + "\"],\"scope\":[\"" + scope + "\"],\"redirect_uri\":[\"" + auth_grant_request_uri + "\"],\"request_uri\":[\"" + redirect_uri + "\"],\"code_verifier\":[\"" + codeVerifier + "\"],\"client_id\":[\"" + client_id + "\"]}";
            request.AddParameter("application/json", body, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);
            string jwtToken = response.Content;

            //Create secretKey_byte using user defined generateAES256Key methode
            byte[] secretKey_byte = generateAES256Key(nonce);
            var decryptedToken = Jose.JWT.Decode(jwtToken, secretKey_byte);         //install Nuget Package "jose-jwt"
            X509Certificate2 cert = new X509Certificate2(Certificate);
            RSACryptoServiceProvider csp = (RSACryptoServiceProvider)cert.PublicKey.Key;
            string json = Jose.JWT.Decode(decryptedToken, csp);
            ViewBag.json = json;

            JsonDocument jsonDocument = JsonDocument.Parse(json);
            JsonElement root = jsonDocument.RootElement;
            ViewBag.name = root.GetProperty("name");
            ViewBag.username = root.GetProperty("username");
            ViewBag.mobile_number = root.GetProperty("mobile_number");
            ViewBag.service_user_id = root.GetProperty("service_user_id");

            try
            {
                ViewBag.aadhaar_ref_no = root.GetProperty("aadhaar_ref_no");
                ViewBag.state = root.GetProperty("state");
            }
            catch (Exception e)
            {
                ViewBag.aadhaar_ref_no = "Aadhar number is not verified";
                ViewBag.state = "Complete your KYC to get address";
            }

            return View();
        }

        //Utils Onwards
        private string hashHMACHex(string message, string secret)
        {
            secret = secret ?? "";
            var encoding = new System.Text.ASCIIEncoding();
            byte[] keyByte = encoding.GetBytes(secret);
            byte[] messageBytes = encoding.GetBytes(message);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
                return Convert.ToBase64String(hashmessage);
            }
        }

        public byte[] generateAES256Key(string seed)
        {
            SHA256 sha256 = SHA256CryptoServiceProvider.Create();
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(seed));
        }

        private static string Encrypt(string plainText, string secret)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(secret);
            var sha = SHA256.Create();
            keyBytes = sha.ComputeHash(keyBytes);
            AesManaged aes = new AesManaged();
            aes.Key = keyBytes;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            var encryptor = aes.CreateEncryptor();
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
            return Convert.ToBase64String(encryptedBytes);
        }

        private static string Decrypt(string encryptedText, string secret)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(secret);
            var sha = SHA256.Create();
            keyBytes = sha.ComputeHash(keyBytes);
            AesManaged aes = new AesManaged();
            aes.Key = keyBytes;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            var decryptor = aes.CreateDecryptor();
            byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
            byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
            return Encoding.UTF8.GetString(decryptedBytes);
        }


    }
}