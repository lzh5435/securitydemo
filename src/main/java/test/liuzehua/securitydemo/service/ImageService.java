package test.liuzehua.securitydemo.service;import com.google.code.kaptcha.impl.DefaultKaptcha;import lombok.extern.slf4j.Slf4j;import org.springframework.beans.factory.annotation.Autowired;import org.springframework.stereotype.Service;import javax.imageio.ImageIO;import javax.servlet.http.HttpServletRequest;import java.awt.image.BufferedImage;import java.io.ByteArrayOutputStream;import java.io.IOException;import java.util.Base64;import java.util.Objects;/** * @author liuzehua * 2020/5/28 **/@Service@Slf4jpublic class ImageService {    @Autowired    private DefaultKaptcha defaultKaptcha;    /**     *利用在线工具测试返回的base64编码的图片验证码字符串是否可以解析     * http://www.vgot.net/test/image2base64.php     *     * 前端显示方法     * <img src="data:image/jpg;base64,${返回的base64字符串}" class="images" border="0"/>     *     * @param param     * @param request     * @return     */    public String createPicVerificationCode(String param,HttpServletRequest request) {        if (Objects.nonNull(param)){            byte[] captchaChallengeAsJpeg;            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();            try {                String verificationCodeText = defaultKaptcha.createText();                //加入到session方便后面验证                request.getSession().setAttribute(param,verificationCodeText);                BufferedImage image = defaultKaptcha.createImage(verificationCodeText);                ImageIO.write(image,"jpg",outputStream);                captchaChallengeAsJpeg = outputStream.toByteArray();                return Base64.getEncoder().encodeToString(captchaChallengeAsJpeg);            }catch (Exception e){                log.error("生成图片验证码异常"+e);                e.printStackTrace();            }finally {                try {                    outputStream.close();                }catch (IOException e){                    log.error("生成图片验证码结束，关闭ByteArrayOutputStream资源失败"+e);                    e.printStackTrace();                }            }        }        return "验证码生成失败，请重试";    }}