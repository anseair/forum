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
import telran.java2022.post.model.Post;

@Component
@RequiredArgsConstructor
public class ChangePostFilter implements Filter {

	final UserAccountRepository userAccountRepository;
	final PostRepository postRepository;
	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		
		//TODO update post (owner)
		if (chenkEndPointUpdate(request.getMethod(), request.getServletPath())) {
			String uri = request.getRequestURI().toString();
			String idPost = uri.substring(uri.lastIndexOf("/")).replace("/", "");
			Post post = postRepository.findById(idPost).orElse(null);
//			System.out.println(idPost);

			UserAccount userAccount = userAccountRepository.findById(request.getUserPrincipal().getName()).get();
			
			if (!post.getAuthor().equals(userAccount.getLogin())) {
				response.sendError(403, "Invalid user");
				return;
			}
		} else {
			
			//TODO delete post (owner + moderator)
			if (chenkEndPointDelete(request.getMethod(), request.getServletPath())) {
				String uri = request.getRequestURI().toString();
				String idPost = uri.substring(uri.lastIndexOf("/")).replace("/", "");
				Post post = postRepository.findById(idPost).orElse(null);
				System.out.println(idPost);
				
//				String uri = request.getServletPath().toString();
//				String idPost = uri.substring(uri.lastIndexOf("/")).replace("/", "");
//				Post post = postRepository.findById(idPost).orElse(null);
//				System.out.println(idPost);
				
				UserAccount userAccount = userAccountRepository.findById(request.getUserPrincipal().getName()).get();
				if (!post.getAuthor().equals(userAccount.getLogin())
						&& !userAccount.getRoles().contains("Moderator".toUpperCase())) {
					response.sendError(403, "Invalid user or no moderator privileges");
					return;
				}
			}
		}

		chain.doFilter(request, response);

}

	private boolean chenkEndPointUpdate(String method, String servletPath) {
		return ("PUT".equalsIgnoreCase(method) && servletPath.matches("/forum/post/\\w+/?"));
	}

	private boolean chenkEndPointDelete(String method, String servletPath) {
		return ("DELETE".equalsIgnoreCase(method) && servletPath.matches("/forum/post/\\w+/?"));
	}
	
}
