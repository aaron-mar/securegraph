package org.securegraph.examples;

import com.altamiracorp.miniweb.App;
import com.altamiracorp.miniweb.StaticFileHandler;
import com.altamiracorp.miniweb.StaticResourceHandler;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public abstract class RouterBase extends HttpServlet {
    private App app;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        app = new App(config);

        initApp(config, app);
    }

    protected void initApp(ServletConfig config, App app) {
        app.get("/", new StaticFileHandler(config, "/index.html"));
        app.get("/jquery.js", new StaticResourceHandler(RouterBase.class, "/org/securegraph/examples/jquery.js", "text/javascript"));
    }

    @Override
    public void service(ServletRequest req, ServletResponse resp) throws ServletException, IOException {
        try {
            app.handle((HttpServletRequest) req, (HttpServletResponse) resp);
        } catch (Exception e) {
            throw new ServletException(e);
        }
    }
}
