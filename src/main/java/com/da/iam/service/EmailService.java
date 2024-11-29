package com.da.iam.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.util.logging.Level;
import java.util.logging.Logger;


@RequiredArgsConstructor
@Service
public class EmailService {
    private final Logger logger = Logger.getLogger(EmailService.class.getName());

//    @Value("${spring.mail.username}")
//    private String from;
//    @Value("${confirmation.registration.url}")
//    private String confirmationRegistrationUrl;
//    private final TemplateEngine templateEngine;
//    private final JavaMailSender javaMailSender;
//
//    public void sendEmail(String to, String subject, String body) {
//        try {
//            SimpleMailMessage simpleMailMessage = new SimpleMailMessage();
//            simpleMailMessage.setFrom(from);
//            simpleMailMessage.setTo(to);
//            simpleMailMessage.setSubject(subject);
//            simpleMailMessage.setText(body);
//            javaMailSender.send(simpleMailMessage);
//        } catch (Exception e) {
//            logger.log(Level.SEVERE, "Error while sending mail");
//        }
//    }
//
//    public void sendConfirmationRegistrationEmail(String to, String token) {
//        sendEmail(to, "Confirm registration", "Click here: " + confirmationRegistrationUrl + "email=" + to + "&token=" + token);
//    }
//
//    public void sendEmailWithHtmlTemplate(String to, String subject, String templateName, String message) {
//        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
//        MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "UTF-8");
//        Context context = new Context();
//        context.setVariable("content", message);
//        try {
//            helper.setTo(to);
//            helper.setSubject(subject);
//            String htmlContent = templateEngine.process(templateName, context);
//            helper.setText(htmlContent, true);
//            javaMailSender.send(mimeMessage);
//        } catch (MessagingException e) {
//            logger.log(Level.SEVERE, "Error while sending mail");
//        }
//    }
}
