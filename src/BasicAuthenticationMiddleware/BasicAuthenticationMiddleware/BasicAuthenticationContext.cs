namespace BasicAuthenticationMiddleware
{
    public class BasicAuthenticationContext
    {
        public BasicAuthenticationContext(string userName, string password)
        {
            UserName = userName;
            Password = password;
        }

        public string UserName { get; set; }
        public string Password { get; set; }
    }
}
