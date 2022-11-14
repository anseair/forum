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

import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java2022.post.dao.PostRepository;
import telran.java2022.post.model.Post;
import telran.java2022.security.context.SecurityContext;
import telran.java2022.security.context.User;

@Component
@RequiredArgsConstructor
public class DeletePostFilter implements Filter {

	final PostRepository postRepository;
	final SecurityContext context;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;

		if (chenkEndPoint(request.getMethod(), request.getServletPath())) {
			String path = request.getServletPath();
			Principal principal = request.getUserPrincipal();
			String[] arr = path.split("/");
			String postId = arr[arr.length - 1];
			
			Post post = postRepository.findById(postId).orElse(null);
			User userAccount = context.getUser(request.getUserPrincipal().getName());
			
			if (post == null) {
				response.sendError(404, "post id = " + postId + " not found");
				return;
			}
			if (!principal.getName().equals(post.getAuthor())
					&& !userAccount.getRoles().contains("Moderator".toUpperCase())) {
				response.sendError(403, "Invalid user or no moderator privileges");
				return;
			}
		}
		chain.doFilter(request, response);
	}

	private boolean chenkEndPoint(String method, String servletPath) {
		return ("DELETE".equalsIgnoreCase(method) && servletPath.matches("/forum/post/\\w+/?"));
	}

}
