using System;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Net.Http;
using System.Text;
using Dapper;

namespace DependencyInjectionWorkshop.Models
{
    public class AuthenticationService
    {
        public bool Verify(string accountId, string pwd, string opt)
        {
            var password = string.Empty;
            using (var connection = new SqlConnection("my connection string"))
            {
                password = connection.Query<string>("spGetUserPassword", new { Id = accountId },
                   commandType: CommandType.StoredProcedure).SingleOrDefault();
            }

            var crypt = new System.Security.Cryptography.SHA256Managed();
            var hash = new StringBuilder();
            var crypto = crypt.ComputeHash(Encoding.UTF8.GetBytes(pwd));
            foreach (var theByte in crypto)
            {
                hash.Append(theByte.ToString("x2"));
            }

            if (password.Equals(hash.ToString()) == false)
                return false;

            var newOTP = string.Empty;
            var httpClient = new HttpClient() { BaseAddress = new Uri("http://joey.com/") };
            var response = httpClient.PostAsJsonAsync("api/otps", accountId).Result;
            if (response.IsSuccessStatusCode)
            {
                newOTP = response.Content.ReadAsAsync<string>().Result;
            }
            else
            {
                throw new Exception($"web api error, accountId:{accountId}");
            }

            return newOTP.Equals(opt);
        }
    }
}