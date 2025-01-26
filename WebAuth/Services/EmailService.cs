using System.Net.Mail;
using System.Net;
using WebAuth.Interfaces.Auth;

namespace WebAuth.Services
{
    public class EmailService : IEmailService
    {
        private readonly string _smtpServer = "smtp.gmail.com";
        private readonly int _smtpPort = 587;
        private readonly string _smtpUser = "men2020v@gmail.com";
        private readonly string _smtpPass = "ryde zvdo lviz krks";

        public async Task SendEmailAsync(string email, string subject, string message)
        {
            using (var smtpClient = new SmtpClient(_smtpServer, _smtpPort))
            {
                smtpClient.Credentials = new NetworkCredential(_smtpUser, _smtpPass);
                smtpClient.EnableSsl = true;

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(_smtpUser),
                    Subject = subject,
                    Body = message,
                    IsBodyHtml = true,
                };

                mailMessage.To.Add(email);

                await smtpClient.SendMailAsync(mailMessage);
            }
        }
    }
}
