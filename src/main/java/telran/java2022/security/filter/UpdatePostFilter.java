package telran.java2022.security.filter;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java2022.accounting.dao.UserAccountRepository;
import telran.java2022.accounting.model.UserAccount;
import telran.java2022.post.dao.PostRepository;
import telran.java2022.post.model.Post;

@Component
@RequiredArgsConstructor
@Order(60)
public class UpdatePostFilter implements Filter {

	final UserAccountRepository userAccountRepository;
	final PostRepository postRepository;
	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		
		//TODO update post (owner)
		if (chenkEndPointUpdate(request.getMethod(), request.getServletPath())) {
			String path = request.getServletPath();
			Principal principal = request.getUserPrincipal();
			String[] arr = path.split("/");
			String postId = arr[arr.length - 1];
			Post post = postRepository.findById(postId).orElse(null);
			if (post == null) {
				response.sendError(404, "post id = " + postId + " not found");
				return;
			}
			String author = post.getAuthor();
			if (!principal.getName().equals(author)) {
				response.sendError(403, "Invalid user");
				return;
			}
		
		}

		chain.doFilter(request, response);

}

	private boolean chenkEndPointUpdate(String method, String servletPath) {
		return ("PUT".equalsIgnoreCase(method) && servletPath.matches("/forum/post/\\w+/?"));
	}


}
