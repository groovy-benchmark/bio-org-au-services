package au.org.biodiversity.nsl
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import org.slf4j.MDC;

public class RequestSequenceFilter implements Filter {

    private static final String REQUEST_SEQUENCE = "xpusostomos.tomcat.valves.requestSequence";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        Object sequence = request.getAttribute(REQUEST_SEQUENCE);
        if (sequence != null) {
            MDC.put("rid", sequence.toString());
        }
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove("rid");
        }
    }
}
