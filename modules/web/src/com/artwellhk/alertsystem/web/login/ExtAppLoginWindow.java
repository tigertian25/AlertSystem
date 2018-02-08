package com.artwellhk.alertsystem.web.login;

import com.haulmont.cuba.web.app.loginwindow.AppLoginWindow;
import java.util.Locale;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.web.App;
import com.haulmont.cuba.web.Connection;
import com.haulmont.cuba.web.auth.ExternallyAuthenticatedConnection;

public class ExtAppLoginWindow extends AppLoginWindow {
	private static final Logger log = LoggerFactory.getLogger(AppLoginWindow.class);
	@Override
	 protected void doLogin() {
	        String login = loginField.getValue();
	        String password = passwordField.getValue() != null ? passwordField.getValue() : "";

	        if (StringUtils.isEmpty(login) || StringUtils.isEmpty(password)) {
	            showNotification(messages.getMainMessage("loginWindow.emptyLoginOrPassword"), NotificationType.WARNING);
	            return;
	        }

	        App app = App.getInstance();

	        try {
	            Connection connection = app.getConnection();

	            Locale selectedLocale = localesSelect.getValue();
	            app.setLocale(selectedLocale);

	            if (loginByRememberMe && webConfig.getRememberMeEnabled()) {
	                doLoginByRememberMe(login, password, selectedLocale);
	            } else if (webAuthConfig.getExternalAuthentication()
	                    && !webAuthConfig.getStandardAuthenticationUsers().contains(login)) {
	                // we use resolved locale for error messages
	                // try to login as externally authenticated user, fallback to regular authentication if enabled
	                authenticateExternally(login, password, selectedLocale);
//	                login = convertLoginString(login);
	                ((ExternallyAuthenticatedConnection) connection).loginAfterExternalAuthentication(login, selectedLocale);
	            } else {
	                doLogin(login, passwordEncryption.getPlainHash(password), selectedLocale);
	            }

	            // locale could be set on the server
	            if (connection.getSession() != null) {
	                Locale loggedInLocale = userSessionSource.getLocale();

	                if (globalConfig.getLocaleSelectVisible()) {
	                    app.addCookie(App.COOKIE_LOCALE, loggedInLocale.toLanguageTag());
	                }
	            }
	        } catch (LoginException e) {
	            log.info("Login failed: {}", e.toString());

	            String message = StringUtils.abbreviate(e.getMessage(), 1000);
	            showLoginException(message);
	        } catch (Exception e) {
	            log.warn("Unable to login", e);

	            showUnhandledExceptionOnLogin(e);
	        }
	    }
}