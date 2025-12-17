using Newtonsoft.Json;
using SharedLibrary;
using System.Diagnostics;
using System.Net;
using System.Text;

namespace RESTClient
{

    internal class Program
    {

        private static RequestEndPoint currentRequest = RequestEndPoint.Idle;
        private static List<RequestEndPoint> requests = new List<RequestEndPoint>();
        private static DateTime timeSinceLastConnectionAttempt;
        private static bool loopRunning = false, approved = false, lastConnectionActive = false;
        private static string? serverPublicKey;
        private static NewUser? newUser = null;
        private static LoginAttempt? loginAttempt = null;
        private static UserReturn? currentUser = null;
        private static Action<string>? messenger;

        private static readonly HttpClient client = new HttpClient();
        private static readonly float interval = 20;
        private static readonly string baseURL = "https://localhost:32773/RESTServer/", clientPrivateKey, clientPublicKey;
        private static readonly object transitionLock = new object();
        private static readonly List<RequestEndPoint> requiresData = new List<RequestEndPoint>
        {

            RequestEndPoint.CreateUser,
            RequestEndPoint.Login

        };

        /// <summary>
        /// Set to request data from server except for requests needing data (Create user, Login, Add Achievement, Add Highscore) - use "RequestWithData" for this instead
        /// </summary>
        public static RequestEndPoint Request
        {

            set
            {

                if (requiresData.Contains(value) && !approved)
                {

                    Debug.WriteLine("Invalid request added, needs data");
                    return;

                }

                if (value != currentRequest)
                {

                    if (value != RequestEndPoint.Idle)
                        timeSinceLastConnectionAttempt = DateTime.UtcNow;

                    lock (transitionLock)
                        if (currentRequest == RequestEndPoint.Idle || value == RequestEndPoint.Idle)
                            currentRequest = value;
                        else if (!requests.Contains(value))
                            requests.Add(value);

                }

                approved = false;

            }

        }

        /// <summary>
        /// Datatransfer object for POSTing an achievement, queues request automatically
        /// </summary>
        private static NewUser NewUser
        {

            set
            {

                newUser = value;

                bool pending = requests.Contains(RequestEndPoint.CreateUser);

                lock (transitionLock)
                    if (newUser == null && pending)
                        requests.Remove(RequestEndPoint.CreateUser);
                    else if (!pending)
                        requests.Add(RequestEndPoint.CreateUser);

            }

        }

        /// <summary>
        /// Datatransfer object for POSTing an achievement, queues request automatically
        /// </summary>
        private static LoginAttempt LoginAttempt
        {

            set
            {

                loginAttempt = value;

                bool pending = requests.Contains(RequestEndPoint.Login);

                lock (transitionLock)
                    if (loginAttempt == null && pending)
                        requests.Remove(RequestEndPoint.Login);
                    else if (!pending)
                        requests.Add(RequestEndPoint.Login);

            }

        }


        static Program()
        {

            SharedMethods.FormRSAKeys(out clientPrivateKey, out clientPublicKey);

            loopRunning = true;

            Task.Run(TaskHandler);

            messenger += Message;

        }

        static void Main(string[] args)
        {

            while (loopRunning)
            {

                Console.WriteLine("Available commands:\nLogin (Login existing user)\nNew (Create a new user)\nKey to get encryption key (need for other operations)\nQuit or Exit to close the program\n");

                string input = Console.ReadLine()!.ToLower();

                if (string.IsNullOrWhiteSpace(input)) continue;

                switch (input)
                {
                    case "login":
                        Console.Clear();
                        LoginData();
                        break;
                    case "new":
                        Console.Clear();
                        CreateUserData();
                        break;
                    case "key":
                        Console.Clear();
                        Console.WriteLine("Trying to retrieve public encryption key from server");
                        Request = RequestEndPoint.GetKey;
                        break;
                    case "quit":
                    case "exit":
                        loopRunning = false;
                        Environment.Exit(0);
                        break;
                    default:
                        break;
                }

            }

        }

        private static void LoginData()
        {

            string email = string.Empty;
            string password = string.Empty;
            bool validEmail = false;
            while (!validEmail)
            {

                Console.WriteLine("Attempting login, please write your email:");
                email = Console.ReadLine()!;

                if (email.ToLower() == "exit")
                    return;

                if (string.IsNullOrWhiteSpace(email) || !email.Contains("@") || !email.Contains("."))
                {

                    Console.Clear();
                    Console.WriteLine("Invalid email, please try again or type \"Exit\" to abort");

                }
                else
                    validEmail = true;

            }

            do
            {
                Console.WriteLine("Type in password or type \"Exit\" to abort - password must be 8 characters or longer");
                password = Console.ReadLine()!;

                if (password.ToLower() == "exit")
                    return;

                if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
                {

                    Console.Clear();
                    Console.WriteLine("Invalid password");

                }

            } while (string.IsNullOrWhiteSpace(password) || password.Length < 8);

            RequestWithData(new LoginAttempt { Email = email, Password = password, PublicKey = clientPublicKey });
            Console.Clear();
            Console.WriteLine("Sending login request...");

        }


        private static void CreateUserData()
        {

            string email = string.Empty;
            string password = string.Empty;
            string username = string.Empty;
            bool validEmail = false;
            while (!validEmail)
            {

                Console.WriteLine("Creating user, please write your email:");
                email = Console.ReadLine()!;

                if (email.ToLower() == "exit")
                    return;

                if (string.IsNullOrWhiteSpace(email) || !email.Contains("@") || !email.Contains("."))
                {

                    Console.Clear();
                    Console.WriteLine("Invalid email, please try again or type \"Exit\" to abort, remember to check for \"@\" and \".\" in your email");

                }
                else
                    validEmail = true;

            }

            do
            {
                Console.WriteLine("Type in desired password or type \"Exit\" to abort - password must be 8 characters or longer");
                password = Console.ReadLine()!;

                if (password.ToLower() == "exit")
                    return;

                if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
                {

                    Console.Clear();
                    Console.WriteLine("Invalid password");

                }

            } while (string.IsNullOrWhiteSpace(password) || password.Length < 8);

            while (string.IsNullOrWhiteSpace(username))
            {

                Console.WriteLine("Type in your desired Username or type \"Exit\" to abort:");
                username = Console.ReadLine()!;

                if (username.ToLower() == "exit")
                    return;

                if (string.IsNullOrWhiteSpace(username))
                    Console.WriteLine("You must type in a username!");

            }

            RequestWithData(new NewUser { Name = username, Email = email, Password = password });
            Console.WriteLine("Attempting to create user...");

        }

        /// <summary>
        /// Handles running and dequeuing tasks
        /// </summary>
        /// <returns>Handled task</returns>
        private static async Task TaskHandler()
        {

            while (loopRunning)
            {

                try
                {

                    if (currentRequest == RequestEndPoint.Idle && requests.Count > 0)
                    {

                        lock (transitionLock)
                        {

                            approved = true;
                            Request = requests[0]; //Alternative combine with RemoveAt to a Queue<RequestEndPoint> since that can't check or remove content other than next in line
                            requests.RemoveAt(0);

                        }

                    }

                    object? needsAttention = null; //Used for generic object handling

                    switch (currentRequest) //State machine for requests
                    {
                        case RequestEndPoint.GetKey:
                            needsAttention = await GetKey();
                            break;
                        case RequestEndPoint.Heartbeat:
                            lastConnectionActive = await Heartbeat();
                            break;
                        case RequestEndPoint.CreateUser:
                            needsAttention = await CreateUser();
                            break;
                        case RequestEndPoint.Login:
                            needsAttention = await Login();
                            break;
                        case RequestEndPoint.Idle:
                        default:
                            break;
                    }

                    if (needsAttention != null)
                        ObjectHandler(needsAttention);

                    if (currentRequest == RequestEndPoint.Idle && !requests.Contains(RequestEndPoint.Heartbeat) && (DateTime.UtcNow - timeSinceLastConnectionAttempt).TotalSeconds >= interval)
                        Request = RequestEndPoint.Heartbeat;

                    await Task.Delay((int)interval); //Ensures server and async runtime isn't swamped by requests

                }
                catch (Exception e)
                {

                    Debug.WriteLine(e);

                }

            }

        }

        /// <summary>
        /// Handles centralized logic for what to do with recieved reply from server dependant on what the reply is
        /// </summary>
        /// <param name="obj">Generic object for polymorphism</param>
        private static void ObjectHandler(object obj)
        {

            switch (obj)
            {
                case UserReturn user:
                    user.Name = SharedMethods.RSADecryptStringToString(user.Name, clientPrivateKey);
                    user.Email = SharedMethods.RSADecryptStringToString(user.Email, clientPrivateKey);
                    currentUser = user;
                    messenger?.Invoke($"User: {user.Name}\nWith email: {user.Email}\nLogged in at {DateTime.UtcNow} - Universal Time");
                    break;
                case ServerReply reply:
                    messenger?.Invoke(reply.Message!);
                    break;
                case KeyString key:
                    if (string.IsNullOrWhiteSpace(key.Key)) break;
                    serverPublicKey = key.Key;
                    messenger?.Invoke("Server returned key");
                    break;
                default:
                    Debug.WriteLine($"DTO with invalid data caught in ObjectHandler {obj}");
                    break;
            }

        }

        /// <summary>
        /// Method to send requests needing data
        /// </summary>
        /// <typeparam name="T">Generic object type</typeparam>
        /// <param name="obj">Object needed for sending requests</param>
        private static void RequestWithData<T>(T obj)
        {

            switch (obj)
            {
                case NewUser user:
                    NewUser = user;
                    break;
                case LoginAttempt attempt:
                    LoginAttempt = attempt;
                    break;
                default:
                    Debug.WriteLine("RequestWithData object contained/was null data, or missing handle logic");
                    break;
            }

        }


        private static async Task<KeyString?> GetKey()
        {

            Request = RequestEndPoint.Idle;

            HttpResponseMessage response = await client.GetAsync(baseURL + RequestEndPoint.GetKey);

            if (response.IsSuccessStatusCode)
            {

                var result = await response.Content.ReadAsStringAsync();
                return JsonConvert.DeserializeObject<KeyString>(result);

            }

            return null;

        }


        private static async Task<bool> Heartbeat()
        {

            Request = RequestEndPoint.Idle;

            var request = new HttpRequestMessage(HttpMethod.Head, baseURL + RequestEndPoint.Heartbeat);
            HttpResponseMessage response = await client.SendAsync(request);

            if (response.IsSuccessStatusCode)
                return true;

            return false;

        }


        private static async Task<ServerReply?> CreateUser()
        {

            Request = RequestEndPoint.Idle;

            if (newUser == null)
            {

                Console.WriteLine("No credentials found");
                return null;

            }

            if (string.IsNullOrWhiteSpace(serverPublicKey))
            {

                Console.WriteLine("No public server key found");
                return null;

            }

            newUser.Name = SharedMethods.RSAEncryptStringToString(newUser.Name, serverPublicKey);
            newUser.Email = SharedMethods.RSAEncryptStringToString(newUser.Email, serverPublicKey);
            newUser.Password = SharedMethods.RSAEncryptStringToString(newUser.Password, serverPublicKey);

            var user = JsonConvert.SerializeObject(newUser);
            HttpContent content = new StringContent(user, Encoding.UTF8, "application/json");

            HttpResponseMessage response = await client.PostAsync(baseURL + RequestEndPoint.CreateUser, content);

            if (response.StatusCode != HttpStatusCode.NotFound)
            {

                var result = await response.Content.ReadAsStringAsync();

                return JsonConvert.DeserializeObject<ServerReply>(result);

            }

            return new ServerReply { Message = "No connection to server" };

        }


        private static async Task<object?> Login()
        {

            Request = RequestEndPoint.Idle;

            if (loginAttempt == null)
            {

                Console.WriteLine("No login credentials found");
                return null;

            }

            if (string.IsNullOrWhiteSpace(serverPublicKey))
            {

                Console.WriteLine("No public server key found");
                return null;

            }

            loginAttempt.Email = SharedMethods.RSAEncryptStringToString(loginAttempt.Email, serverPublicKey);
            loginAttempt.Password = SharedMethods.RSAEncryptStringToString(loginAttempt.Password, serverPublicKey);

            var login = JsonConvert.SerializeObject(loginAttempt);
            HttpContent content = new StringContent(login, Encoding.UTF8, "application/json");

            HttpResponseMessage response = await client.PostAsync(baseURL + RequestEndPoint.Login, content);

            if (response.IsSuccessStatusCode)
            {

                var result = await response.Content.ReadAsStringAsync();

                return JsonConvert.DeserializeObject<UserReturn>(result);

            }
            else if (response.StatusCode != HttpStatusCode.NotFound)
            {

                var result = await response.Content.ReadAsStringAsync();

                return JsonConvert.DeserializeObject<ServerReply>(result);

            }

            return new ServerReply { Message = "No reply from server" };

        }

        private static void Message(string message)
        {

            Console.WriteLine(message);

        }

    }

}