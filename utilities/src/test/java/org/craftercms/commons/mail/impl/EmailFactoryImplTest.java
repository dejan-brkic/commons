package org.craftercms.commons.mail.impl;

import java.io.StringWriter;
import java.util.Collections;
import java.util.Map;
import javax.mail.Message;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import freemarker.template.Configuration;
import freemarker.template.Template;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.ui.freemarker.FreeMarkerConfigurationFactory;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Unit tests for {@link EmailFactoryImpl}.
 *
 * @author avasquez
 */
public class EmailFactoryImplTest {

    private static final String FROM = "noreply@craftersoftware.com";
    private static final String[] TO = { "user1@craftersoftware.com" };
    private static final String[] CC = { "user2@craftersoftware.com" };
    private static final String[] BCC = { "user3@craftersoftware.com" };
    private static final String REPLY_TO = "admin@craftersoftware.com";
    private static final String SUBJECT = "Test";
    private static final String BODY = "This is a test email";
    
    private static final String ENCODING = "UTF-8";
    private static final String TEMPLATE_NAME = "test.ftl";

    private JavaMailSenderImpl mailSender;
    private Configuration freeMarkerConfig;
    private EmailFactoryImpl emailFactory;

    @Before
    public void setUp() throws Exception {
        mailSender = createMailSender();
        freeMarkerConfig = createFreeMarkerConfig();

        emailFactory = new EmailFactoryImpl();
        emailFactory.setMailSender(mailSender);
        emailFactory.setFreeMarkerConfig(freeMarkerConfig);
        emailFactory.setTemplateEncoding(ENCODING);
    }

    @Test
    public void testGetEmailWithBodyParam() throws Exception {
        EmailImpl email = (EmailImpl)emailFactory.getEmail(FROM, TO, CC, BCC, REPLY_TO, SUBJECT, BODY, false);

        assertNotNull(email);

        MimeMessage msg = email.message;

        assertArrayEquals(InternetAddress.parse(FROM), msg.getFrom());
        assertArrayEquals(InternetAddress.parse(StringUtils.join(TO)), msg.getRecipients(Message.RecipientType.TO));
        assertArrayEquals(InternetAddress.parse(StringUtils.join(CC)), msg.getRecipients(Message.RecipientType.CC));
        assertArrayEquals(InternetAddress.parse(StringUtils.join(BCC)), msg.getRecipients(Message.RecipientType.BCC));
        assertArrayEquals(InternetAddress.parse(REPLY_TO), msg.getReplyTo());
        assertEquals(SUBJECT, msg.getSubject());
        assertEquals(BODY, msg.getContent());
    }

    @Test
    public void testGetEmailWithBodyTemplate() throws Exception {
        Map<String, Object> model = Collections.<String, Object>singletonMap("name", "John Doe");
        String body = processTemplate(TEMPLATE_NAME, model);

        EmailImpl email = (EmailImpl)emailFactory.getEmail(FROM, TO, CC, BCC, REPLY_TO, SUBJECT, TEMPLATE_NAME,
                                                           model, false);

        assertNotNull(email);

        MimeMessage msg = email.message;

        assertArrayEquals(InternetAddress.parse(FROM), msg.getFrom());
        assertArrayEquals(InternetAddress.parse(StringUtils.join(TO)), msg.getRecipients(Message.RecipientType.TO));
        assertArrayEquals(InternetAddress.parse(StringUtils.join(CC)), msg.getRecipients(Message.RecipientType.CC));
        assertArrayEquals(InternetAddress.parse(StringUtils.join(BCC)), msg.getRecipients(Message.RecipientType.BCC));
        assertArrayEquals(InternetAddress.parse(REPLY_TO), msg.getReplyTo());
        assertEquals(SUBJECT, msg.getSubject());
        assertEquals(body, msg.getContent());
    }

    private JavaMailSenderImpl createMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost("localhost");
        mailSender.setPort(25);
        mailSender.setProtocol("smtp");
        mailSender.setDefaultEncoding(ENCODING);

        return mailSender;
    }


    private Configuration createFreeMarkerConfig() throws Exception {
        FreeMarkerConfigurationFactory factory = new FreeMarkerConfigurationFactory();
        factory.setDefaultEncoding(ENCODING);
        factory.setTemplateLoaderPath("classpath:mail/templates");

        return factory.createConfiguration();
    }

    protected String processTemplate(String templateName, Object templateModel) throws Exception {
        Template template = freeMarkerConfig.getTemplate(templateName, ENCODING);
        StringWriter out = new StringWriter();

        template.process(templateModel, out);

        return out.toString();
    }

}