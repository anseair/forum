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
import telran.java2022.post.dao.PostRepository;

@Component
@RequiredArgsConstructor
public class AddPostAndCommentFilter implements Filter {

	final PostRepository postRepository;
	final UserAccountRepository userAccountRepository;
	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		
		//TODO add post and add comment
		if (chenkEndPointAddPost(request.getMethod(), request.getServletPath())) {
			String uri = request.getRequestURI().toString();
			String author = uri.substring(uri.lastIndexOf("/")).replace("/", "");
//			System.out.println(author);

			UserAccount userAccount = userAccountRepository.findById(request.getUserPrincipal().getName()).get();
			if (!author.equals(userAccount.getLogin())) {
				response.sendError(403, "Invalid user");
				return;
			}
		}

		chain.doFilter(request, response);
	}


	private boolean chenkEndPointAddPost(String method, String servletPath) {
		return ("POST".equalsIgnoreCase(method) && servletPath.matches("/forum/post/\\w+/?")) || ("PUT".equalsIgnoreCase(method) && servletPath.matches("/forum/post/\\w+/comment/\\w+/?"));
	}
	
}
