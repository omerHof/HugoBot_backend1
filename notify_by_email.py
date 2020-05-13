import smtplib
import ssl

sender_email = 'bothugo86@gmail.com'
password = 'Naruto123#0'

def send_an_email(message, receiver_email):
    port = 465  # For SSL
    smtp_server = "smtp.gmail.com"

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message)