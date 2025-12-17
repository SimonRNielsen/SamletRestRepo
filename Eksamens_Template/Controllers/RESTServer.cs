using Microsoft.AspNetCore.Mvc;
using SharedLibrary;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Text;

namespace Eksamens_Template.Controllers
{

    [ApiController]
    [Route("[controller]")]
    public class RESTServer : ControllerBase
    {

        private const string dataDirectory = "tmp";
        private static readonly string serverPrivateKey, serverPublicKey, usersFile = dataDirectory + "/users.json";
        private static readonly object fileLock = new object();

        static RESTServer()
        {

            SharedMethods.FormRSAKeys(out serverPrivateKey, out serverPublicKey);

            lock (fileLock)
            {

                if (!Directory.Exists(dataDirectory))
                    Directory.CreateDirectory(dataDirectory);

                if (!System.IO.File.Exists(usersFile))
                    System.IO.File.WriteAllText("[]", usersFile); //Blank .json file

            }

        }

        [HttpGet("GetKey")]
        public ActionResult<string> GetPublicKey()
        {

            KeyString key = new KeyString { Key = serverPublicKey };

            var json = JsonConvert.SerializeObject(key);

            return Ok(json);

        }

        [HttpHead("Heartbeat")]
        public ActionResult Ping()
        {

            return Ok();

        }

        [HttpPost("CreateUser")]
        public ActionResult<string> CreateUser([FromBody] NewUser newUser)
        {

            lock (fileLock)
            {

                string userList = System.IO.File.ReadAllText(usersFile);
                List<StoredUser> users = JsonConvert.DeserializeObject<List<StoredUser>>(userList)!;
                newUser.Email = SharedMethods.RSADecryptStringToString(newUser.Email, serverPrivateKey);

                if (users.Any(x => x.Email.ToLower() == newUser.Email.ToLower()))
                    return Conflict(new ServerReply { Message = "Error creating new user" });

                newUser.Password = SharedMethods.RSADecryptStringToString(newUser.Password, serverPrivateKey);
                newUser.Name = SharedMethods.RSADecryptStringToString(newUser.Name, serverPrivateKey);

                byte[] salt = new byte[16];
                RandomNumberGenerator.Fill(salt);

                byte[] passPlusSalt = Encoding.UTF8.GetBytes(newUser.Password).Concat(salt).ToArray();
                using SHA256 sha256 = SHA256.Create();
                byte[] hashedPassWithSalt = sha256.ComputeHash(passPlusSalt);

                StoredUser user = new StoredUser
                {

                    Name = newUser.Name,
                    Email = newUser.Email,
                    Password = hashedPassWithSalt,
                    Salt = salt

                };

                users.Add(user);

                var json = JsonConvert.SerializeObject(users, Formatting.Indented);

                System.IO.File.WriteAllText(usersFile, json);

                return Ok(new ServerReply { Message = "Created new user" });

            }

        }

        [HttpPost("Login")]
        public ActionResult<string> Login([FromBody] LoginAttempt attempt)
        {

            if (attempt == null)
                return BadRequest(new ServerReply { Message = "Null data sent" });

            string badAttempt = "Error logging in";

            string userList;

            lock (fileLock)
                userList = System.IO.File.ReadAllText(usersFile);
            List<StoredUser> users = JsonConvert.DeserializeObject<List<StoredUser>>(userList)!;
            attempt.Email = SharedMethods.RSADecryptStringToString(attempt.Email, serverPrivateKey);

            if (users.Count == 0)
                return BadRequest(new ServerReply { Message = "No users found" });

            if (!users.Any(x => x.Email.ToLower() == attempt.Email.ToLower()))
                return Unauthorized(new ServerReply { Message = badAttempt });

            StoredUser compare = users.Find(x => x.Email.ToLower() == attempt.Email.ToLower())!;

            attempt.Password = SharedMethods.RSADecryptStringToString(attempt.Password, serverPrivateKey);

            byte[] attemptPassPlusSalt = Encoding.UTF8.GetBytes(attempt.Password).Concat(compare.Salt).ToArray();
            using SHA256 sha256 = SHA256.Create();
            byte[] passPlusSaltHash = sha256.ComputeHash(attemptPassPlusSalt);

            if (!passPlusSaltHash.SequenceEqual(compare.Password))
                return Unauthorized(new ServerReply { Message = badAttempt });

            UserReturn user = new UserReturn
            {

                Name = SharedMethods.RSAEncryptStringToString(compare.Name, attempt.PublicKey),
                Email = SharedMethods.RSAEncryptStringToString(compare.Email, attempt.PublicKey)

            };

            var json = JsonConvert.SerializeObject(user);

            return Ok(json);

        }

    }
}
