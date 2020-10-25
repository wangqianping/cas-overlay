package config;

import org.apache.shiro.crypto.hash.Md5Hash;
import org.apereo.cas.authentication.*;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.security.auth.login.AccountException;
import javax.security.auth.login.FailedLoginException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 自定义认证策略
 */
public class CustomUsernamePasswordAuthentication extends AbstractUsernamePasswordAuthenticationHandler {

    public CustomUsernamePasswordAuthentication(String name, ServicesManager servicesManager, PrincipalFactory principalFactory, Integer order) {
        super(name, servicesManager, principalFactory, order);
    }

    @Override
    protected AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal(UsernamePasswordCredential credential, String originalPassword) throws GeneralSecurityException, PreventedException {

        String username = credential.getUsername();
        String password = credential.getPassword();

        System.out.println("username : " + username);
        System.out.println("password : " + password);
        System.out.println("originalPassword : " + originalPassword);

        // JDBC模板依赖于连接池来获得数据的连接，所以必须先要构造连接池
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("com.mysql.jdbc.Driver");
        dataSource.setUrl("jdbc:mysql://localhost:3306/jeecg-boot");
        dataSource.setUsername("root");
        dataSource.setPassword("123456");

        // 创建JDBC模板
        JdbcTemplate jdbcTemplate = new JdbcTemplate();
        jdbcTemplate.setDataSource(dataSource);

        String sql = "SELECT * FROM sys_user WHERE username = ?";

        Map<String, Object> stringObjectMap = jdbcTemplate.queryForMap(sql, new Object[]{username});
        String name = stringObjectMap.get("username").toString();
        String pwd = stringObjectMap.get("password").toString();
        String salt = stringObjectMap.get("salt").toString();
        String user_id = stringObjectMap.get("id").toString();

        System.out.println("database username : " + name);
        System.out.println("database password : " + pwd);
        System.out.println("database salt : " + salt);

        if (stringObjectMap == null) {
            throw new AccountException("Sorry, username not found!");
        }

        if (!originalPassword.equals("admin123")) {
            throw new FailedLoginException("Sorry, password not correct!");
        } else {
            //可自定义返回给客户端的多个属性信息
            HashMap<String, Object> returnInfo = new HashMap<>();
            returnInfo.put("username", name);
            returnInfo.put("password", originalPassword);
            returnInfo.put("userId", user_id);
            final List<MessageDescriptor> list = new ArrayList<>();

            AuthenticationHandlerExecutionResult handlerResult = createHandlerResult(credential,
                    this.principalFactory.createPrincipal(username, returnInfo), list);
            System.out.println("======成功返回了=====" + handlerResult.toString());
            return handlerResult;
        }
    }
}
