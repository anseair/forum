package telran.java2022.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java2022.accounting.dao.UserAccountRepository;
import telran.java2022.accounting.model.UserAccount;

@Component
@RequiredArgsConstructor
public class UpdateUserFilter implements Filter {

	final UserAccountRepository userAccountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		
		if (chenkEndPoint(request.getMethod(), request.getServletPath())) {
			String uri = request.getRequestURI().toString();
			String user = uri.substring(uri.lastIndexOf("/")).replace("/", "");
			UserAccount userAccount = userAccountRepository.findById(request.getUserPrincipal().getName()).get();
			if (!user.equals(userAccount.getLogin())) {
				response.sendError(403, "No such user exists");
				return;
			}
		}
		chain.doFilter(request, response);
	}

	private boolean chenkEndPoint(String method, String servletPath) {
		return ("PUT".equalsIgnoreCase(method) && servletPath.matches("/account/user/\\w+/?"));
	}

}
