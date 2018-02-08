package com.artwellhk.alertsystem.web.login;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.inject.Inject;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.commons.lang.StringUtils;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.security.crypto.codec.Base64;

import com.haulmont.cuba.core.global.Messages;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.web.auth.CubaAuthProvider;
import com.haulmont.cuba.web.auth.LdapAuthProvider;
import com.haulmont.cuba.web.auth.WebAuthConfig;

public class LDAPAuthProvider implements CubaAuthProvider {

	@Inject
	protected Messages messages;

	@Inject
	protected WebAuthConfig webAuthConfig;

	protected LdapContextSource ldapContextSource;

	protected LdapTemplate ldapTemplate;

	@Override
	public void authenticate(String login, String password, Locale messagesLocale) throws LoginException {

		// if (!ldapTemplate.authenticate(LdapUtils.emptyLdapName(), login, password)) {
		if (!authentication(login, password)) {
			throw new LoginException(messages.formatMessage(LdapAuthProvider.class,
					"LoginException.InvalidLoginOrPassword", messagesLocale, login));
		}
	}

	public boolean authentication(String userName, String pwd) {
		boolean correct_flg = false;
		LdapQuery query = LdapQueryBuilder.query().base("ou=Users,domainName=artwell-hk.com")
				.attributes("mail", "userpassword").where("objectclass").is("mailUser").and("mail").is(userName);
		/**
		 * @return ldap password
		 */
		String ldapPwd = null;
		List<String> rs = ldapTemplate.search(query, new AttributesMapper<String>() {
			@Override
			public String mapFromAttributes(Attributes attrs) throws NamingException {
				Object tempPwd = attrs.get("userpassword").get();
				byte[] pwd = (byte[]) tempPwd;
				return new String(pwd);
			}
		});
		if (rs != null && rs.size() > 0) {
			ldapPwd = rs.get(0);
		} else {
			return false;
		}

		correct_flg = verifyByPwd(ldapPwd, pwd);
		return correct_flg;
	}

	public boolean verifyByPwd(String ldappw, String inputpw) {

		// MessageDigest 提供了消息摘要算法，如 MD5 或 SHA，的功能，这里LDAP使用的是SHA-1
		MessageDigest md;
		boolean flg = false;
		try {
			md = MessageDigest.getInstance("SHA-1");

			/**
			 * ldap中的密码 例:
			 */
			// 取出加密字符
			if (ldappw.indexOf("{SSHA}") != -1) {
				ldappw = ldappw.substring(6);
			}

			// 解码BASE64
			byte[] ldappwbyte = Base64.decode(ldappw.getBytes());
			byte[] shacode;
			byte[] salt;

			// 前20位是SHA-1加密段，20位后是最初加密时的随机明文
			if (ldappwbyte.length <= 20) {
				shacode = ldappwbyte;
				salt = new byte[0];
			} else {
				shacode = new byte[20];
				salt = new byte[ldappwbyte.length - 20];
				System.arraycopy(ldappwbyte, 0, shacode, 0, 20);
				System.arraycopy(ldappwbyte, 20, salt, 0, salt.length);
			}

			// 把用户输入的密码添加到摘要计算信息
			md.update(inputpw.getBytes());
			// 把随机明文添加到摘要计算信息
			md.update(salt);

			// 按SSHA把当前用户密码进行计算
			byte[] inputpwbyte = md.digest();

			// 返回校验结果
			flg = MessageDigest.isEqual(shacode, inputpwbyte);

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return flg;

	}

	protected String buildPersonFilter(String login) {
		AndFilter filter = new AndFilter();
		filter.and(new EqualsFilter("objectclass", "person"))
				.and(new EqualsFilter(webAuthConfig.getLdapUserLoginField(), login));
		return filter.encode();
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		ldapContextSource = new LdapContextSource();

		checkRequiredConfigProperties(webAuthConfig);

		ldapContextSource.setBase(webAuthConfig.getLdapBase());
		List<String> ldapUrls = webAuthConfig.getLdapUrls();
		ldapContextSource.setUrls(ldapUrls.toArray(new String[ldapUrls.size()]));
		ldapContextSource.setUserDn(webAuthConfig.getLdapUser());
		ldapContextSource.setPassword(webAuthConfig.getLdapPassword());

		ldapContextSource.afterPropertiesSet();

		ldapTemplate = new LdapTemplate(ldapContextSource);
		ldapTemplate.setIgnorePartialResultException(true);
	}

	protected void checkRequiredConfigProperties(WebAuthConfig webAuthConfig) {
		List<String> missingProperties = new ArrayList<>();
		if (StringUtils.isBlank(webAuthConfig.getLdapBase())) {
			missingProperties.add("cuba.web.ldap.base");
		}
		if (webAuthConfig.getLdapUrls().isEmpty()) {
			missingProperties.add("cuba.web.ldap.urls");
		}
		if (StringUtils.isBlank(webAuthConfig.getLdapUser())) {
			missingProperties.add("cuba.web.ldap.user");
		}
		if (StringUtils.isBlank(webAuthConfig.getLdapPassword())) {
			missingProperties.add("cuba.web.ldap.password");
		}

		if (!missingProperties.isEmpty()) {
			throw new IllegalStateException("Please configure required application properties for LDAP integration: \n"
					+ StringUtils.join(missingProperties, "\n"));
		}
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		chain.doFilter(request, response);
	}

	@Override
	public void destroy() {
	}

}
