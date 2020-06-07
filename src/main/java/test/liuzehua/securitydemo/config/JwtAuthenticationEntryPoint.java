package test.liuzehua.securitydemo.config;import com.alibaba.fastjson.JSONObject;import org.springframework.security.core.AuthenticationException;import org.springframework.security.web.AuthenticationEntryPoint;import org.springframework.stereotype.Component;import javax.servlet.ServletException;import javax.servlet.http.HttpServletRequest;import javax.servlet.http.HttpServletResponse;import java.io.IOException;/** * @author liuzehua * 2020/5/20 **/@Componentpublic class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {    @Override    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {        httpServletResponse.setCharacterEncoding("UTF-8");        httpServletResponse.setContentType("application/json; charset=utf-8");        httpServletResponse.getWriter().write(new JSONObject(){{put("code","5010");put("msg","token错误");}}.toString());    }}