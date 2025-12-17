namespace SharedLibrary
{
    public enum RequestEndPoint
    {

        Idle,
        GetKey,
        Heartbeat,
        CreateUser,
        Login

    }

    public class KeyString
    {

        public required string Key { get; set; }

    }

    public class ServerReply
    {

        public string? Message { get; set; }

    }

    public class UserReturn
    {

        public required string Name { get; set; }

        public required string Email { get; set; }

    }

    public class LoginAttempt
    {

        public required string Email { get; set; }

        public required string Password { get; set; }

        public required string PublicKey { get; set; }

    }

    public class NewUser
    {

        public required string Name { get; set; }

        public required string Email { get; set; }

        public required string Password { get; set; }

    }

    public class StoredUser
    {

        public required string Name { get; set; }

        public required string Email { get; set; }

        public required byte[] Password { get; set; }

        public required byte[] Salt { get; set; }

    }
}
