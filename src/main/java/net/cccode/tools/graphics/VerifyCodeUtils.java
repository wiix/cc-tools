package net.cccode.tools.graphics;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.AffineTransform;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.ImageOutputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class VerifyCodeUtils {

	//Algerian或黑体，去掉0,o,1,i,j,l,I,9,g,q,6,b,p等容易混淆的字符
	public static final String VERIFY_CODES = "234578acdefhkmnrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
	private static Random random = new Random();
	private static final Log logger = LogFactory.getLog(VerifyCodeUtils.class);


	/**
	 * 使用系统默认字符源生成验证码
	 * 
	 * @param verifySize 验证码长度
	 * @return
	 */
	public static String generateVerifyCode(int verifySize) {
		return generateVerifyCode(verifySize, VERIFY_CODES);
	}


	/**
	 * 使用指定源生成验证码
	 * 
	 * @param verifySize 验证码长度
	 * @param sources 验证码字符源
	 * @return
	 */
	public static String generateVerifyCode(int verifySize, String sources) {
		if (sources == null || sources.length() == 0) {
			sources = VERIFY_CODES;
		}
		int codesLen = sources.length();
		Random rand = new Random(System.currentTimeMillis());
		StringBuilder verifyCode = new StringBuilder(verifySize);
		for (int i = 0; i < verifySize; i++) {
			verifyCode.append(sources.charAt(rand.nextInt(codesLen - 1)));
		}
		return verifyCode.toString();
	}


	/**
	 * 生成随机验证码文件,并返回验证码值
	 * 
	 * @param w
	 * @param h
	 * @param outputFile
	 * @param verifySize
	 * @return
	 * @throws IOException
	 */
	public static String outputVerifyImage(int w, int h, File outputFile, int verifySize) throws IOException {
		String verifyCode = generateVerifyCode(verifySize);
		outputImage(w, h, outputFile, verifyCode);
		return verifyCode;
	}


	/**
	 * 输出随机验证码图片流,并返回验证码值
	 * 
	 * @param w
	 * @param h
	 * @param os
	 * @param verifySize
	 * @return
	 * @throws IOException
	 */
	public static String outputVerifyImage(int w, int h, OutputStream os, int verifySize) throws IOException {
		String verifyCode = generateVerifyCode(verifySize);
		outputImage(w, h, os, verifyCode);
		return verifyCode;
	}


	/**
	 * 生成指定验证码图像文件
	 * 
	 * @param w
	 * @param h
	 * @param outputFile
	 * @param code
	 * @throws IOException
	 */
	public static void outputImage(int w, int h, File outputFile, String code) throws IOException {
		if (outputFile == null) {
			return;
		}
		File dir = outputFile.getParentFile();
		if (!dir.exists()) {
			dir.mkdirs();
		}
		try {
			outputFile.createNewFile();
			FileOutputStream fos = new FileOutputStream(outputFile);
			outputImage(w, h, fos, code);
			fos.close();
		} catch (IOException e) {
			throw e;
		}
	}


	/**
	 * 
	 * @param w
	 * @param h
	 * @param outputFile
	 * @param minute
	 * @param times
	 * @throws IOException
	 */
	public static void outputError(int w, int h, File outputFile, int minute, int times, int waitMinute) throws IOException {
		if (outputFile == null) {
			return;
		}
		File dir = outputFile.getParentFile();
		if (!dir.exists()) {
			dir.mkdirs();
		}
		try {
			outputFile.createNewFile();
			FileOutputStream fos = new FileOutputStream(outputFile);
			outputImage(fos, createErrorImage(w, h, minute, times, waitMinute));
			fos.close();
		} catch (IOException e) {
			throw e;
		}
	}


	/**
	 * 
	 * @param w
	 * @param h
	 * @param outputFile
	 * @param code
	 * @param index
	 */
	public static void outputGIF(int w, int h, File outputFile, String code, int totalFrames) {
		int index = random.nextInt(totalFrames);
		try {
			// 指定Frame的文件
			AnimatedGifEncoder e = new AnimatedGifEncoder();
			OutputStream os = new FileOutputStream(outputFile); //输出图片
			e.start(os);// 开始处理
			e.setQuality(15); //设置图片质量
			e.setRepeat(0); //设置循环
			for (int i = 0; i < totalFrames; i++) {
				if (i == index) {
					e.setDelay(3200); // 设置延迟时间
					e.addFrame(createImage(w, h, code));// 循环加入Frame
				} else {
					String verifyCode = generateVerifyCode(code.length());
					e.setDelay(150); // 设置延迟时间
					e.addFrame(createImage(w, h, verifyCode));// 循环加入Frame
				}
			}
			e.finish();
		} catch (Exception e) {
			System.out.println(e);
			e.printStackTrace();
		}
	}


	public static void outputImage(int w, int h, OutputStream os, String code) throws IOException {
		BufferedImage image = createImage(w, h, code);
		//ImageIO.write(image, "JPEG", os);
		outputImage(os, image);
	}


	/**
	 * http://wiki.apache.org/tomcat/FAQ/KnownIssues
	 * </p>
	 * An alternative would be to write the Image contents to a
	 * ByteArrayOutputStream,
	 * and using its writeTo() method to write the contents to the Servlet's
	 * Response. However that would require some additional memory, as the
	 * contents have
	 * to be buffered.
	 * 
	 * @param os
	 * @param image
	 * @throws IOException
	 */
	public static void outputImage(OutputStream os, BufferedImage image) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ImageOutputStream ios = ImageIO.createImageOutputStream(baos);
		ImageWriter writer = ImageIO.getImageWritersByFormatName("jpeg").next();
		ImageWriteParam iwp = writer.getDefaultWriteParam();
		iwp.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
		iwp.setCompressionQuality(0.95f);
		writer.setOutput(ios);
		writer.write(null, new IIOImage(image, null, null), iwp);
		writer.dispose();
		baos.writeTo(os);
	}


	/**
	 * http://wiki.apache.org/tomcat/FAQ/KnownIssues
	 * 
	 * An alternative would be to write the Image contents to a
	 * ByteArrayOutputStream,
	 * and using its writeTo() method to write the contents to the Servlet's
	 * Response. However that would require some additional memory, as the
	 * contents have
	 * to be buffered.
	 * 
	 * @param os
	 * @param image
	 * @throws IOException
	 */
	public static void outputImage2(OutputStream os, BufferedImage image) throws IOException {

		try (ImageOutputStream ios = ImageIO.createImageOutputStream(new ImageIOOutputStream(os))) {
			ImageWriter writer = ImageIO.getImageWritersByFormatName("jpeg").next();
			ImageWriteParam iwp = writer.getDefaultWriteParam();
			iwp.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
			iwp.setCompressionQuality(0.95f);
			writer.setOutput(ios);
			writer.write(null, new IIOImage(image, null, null), iwp);
			os.flush();
			writer.dispose();
		} catch (IOException ex) {
			logger.debug(ex);//org.apache.catalina.connector.ClientAbortException: java.io.IOException: APR error: -730053
			// Client aborted connection
		}

		//		IIOMetadata imageMetaData = writer.getDefaultImageMetadata(new ImageTypeSpecifier(image), null);
		//		Element tree = (Element) imageMetaData.getAsTree("javax_imageio_jpeg_image_1.0");
		//		Element jfif = (Element) tree.getElementsByTagName("app0JFIF").item(0);
		//		jfif.setAttribute("Xdensity", Integer.toString(300));
		//		jfif.setAttribute("Ydensity", Integer.toString(300));
		//		writer.write(imageMetaData, new IIOImage(image, null, null), iwp);

	}


	/**
	 * 输出指定验证码图片流
	 * 
	 * @param w
	 * @param h
	 * @param os
	 * @param code
	 * @throws IOException
	 */
	public static BufferedImage createImage(int w, int h, String code) throws IOException {
		BufferedImage image = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
		Graphics2D g2 = image.createGraphics();
		g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		Color c = getRandColor(200, 250);
		g2.setColor(c);// 设置背景色
		g2.fillRect(0, 0, w, h);

		// 添加噪点
		float yawpRate = 0.03f;// 噪声率

		int area = (int) (yawpRate * w * h);
		for (int i = 0; i < area; i++) {
			int x = random.nextInt(w);
			int y = random.nextInt(h);
			int rgb = getRandomIntColor();
			image.setRGB(x, y, rgb);
		}

		//绘制干扰线
		for (int i = 0; i < 5; i++) {
			g2.setColor(getRandColor(130, 190));
			int x = random.nextInt(w);
			int y = random.nextInt(h);
			int xl = random.nextInt(w / 2) + w / 7;
			int yl = random.nextInt(h / 2) + h / 7;
			g2.setStroke(new BasicStroke(random.nextInt(h / 22) + h / 22));
			g2.drawLine(x, y, x + xl, y + yl);
		}

		//		int fontSize = (int) (h * 0.86);
		//		//Font font = new Font("宋体", Font.ITALIC, fontSize);
		//		g2.setFont(font);

		char[] chars = code.toCharArray();
		int verifySize = code.length();

		for (int i = 0; i < verifySize; i++) {
			int fontSize = (int) (h - random.nextInt(h / 4) * 0.88);
			g2.setFont(new Font("黑体", random.nextBoolean() ? Font.BOLD : Font.ITALIC, fontSize));

			if (random.nextBoolean()) {
				g2.setColor(getRandColor(100, 180));
			}
			//			AffineTransform affine = new AffineTransform();
			//			affine.setToRotation(Math.PI / 4 * random.nextDouble() * (random.nextBoolean() ? 1 : -1), (w / verifySize) * i + fontSize / 2, h / 2);
			//			g2.setTransform(affine);
			//			g2.drawChars(chars, i, 1, ((w + 5 - random.nextInt(20)) / verifySize) * i - w / 15 * (i - verifySize / 2), h / 2 + fontSize / 2 - h / 8);

			int xx = ((w - random.nextInt(20)) / verifySize) * i - w / 20 * (i - verifySize / 2);
			int yy = h / 2 + fontSize / 2 - h / 10;
			AffineTransform affine = new AffineTransform();
			affine.setToRotation(Math.PI / 4 * random.nextDouble() * (random.nextBoolean() ? 1 : -1), xx + fontSize / 2, yy - fontSize / 2);
			g2.setTransform(affine);
			g2.drawChars(chars, i, 1, xx, yy);

			//绘制干扰线
			int x = random.nextInt(w);
			int y = random.nextInt(h);
			int xl = random.nextInt(w / 2) + w / 8;
			int yl = random.nextInt(h / 2) + h / 8;
			g2.setStroke(new BasicStroke(random.nextInt(h / 25) + h / 25));
			g2.drawLine(x, y, x - xl, y + yl);

		}

		g2.dispose();

		g2 = image.createGraphics();
		g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		//		//绘制干扰线
		//		for (int i = 0; i < 5; i++) {
		//			g2.setColor(getRandColor(130, 190));
		//			int x = random.nextInt(w);
		//			int y = random.nextInt(h);
		//			int xl = random.nextInt(10 + w / 2) + 8;
		//			int yl = random.nextInt(5 + h / 2) + 4;
		//			g2.setStroke(new BasicStroke(random.nextInt(h / 35) + h / 30));
		//			g2.drawLine(x, y, x - xl, y + yl);
		//		}

		// 添加噪点
		yawpRate = 0.01f;// 噪声率
		area = (int) (yawpRate * w * h);
		for (int i = 0; i < area; i++) {
			int x = random.nextInt(w);
			int y = random.nextInt(h);
			int rgb = getRandomIntColor();
			image.setRGB(x, y, rgb);
		}

		shear(g2, w, h, c);// 使图片扭曲

		g2.dispose();

		return image;
		//ImageIO.write(image, "jpg", os);
	}


	/**
	 * 
	 * @param w
	 * @param h
	 * @param minute
	 * @param times
	 * @return
	 * @throws IOException
	 */
	public static BufferedImage createErrorImage(int w, int h, int minute, int times, int waitMinute) throws IOException {
		BufferedImage image = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
		Graphics2D g2 = image.createGraphics();

		Color c = getRandColor(200, 250);
		g2.setColor(c);// 设置背景色
		g2.fillRect(0, 2, w, h - 4);

		// 添加噪点
		float yawpRate = 0.03f;// 噪声率

		int area = (int) (yawpRate * w * h);
		for (int i = 0; i < area; i++) {
			int x = random.nextInt(w);
			int y = random.nextInt(h);
			int rgb = getRandomIntColor();
			image.setRGB(x, y, rgb);
		}

		//绘制干扰线
		for (int i = 0; i < 5; i++) {
			g2.setColor(getRandColor(130, 190));
			int x = random.nextInt(w);
			int y = random.nextInt(h);
			int xl = random.nextInt(10 + w / 2) + 8;
			int yl = random.nextInt(5 + h / 2) + 4;
			g2.setStroke(new BasicStroke(random.nextInt(h / 25) + h / 25));
			g2.drawLine(x, y, x + xl, y + yl);
		}

		int fontSize = (int) (h * 0.3);
		g2.setFont(new Font("黑体", Font.ITALIC, fontSize));

		char[] chars = (minute + "分内请求超 " + times + "次").toCharArray();
		int verifySize = chars.length;
		for (int i = 0; i < verifySize; i++) {
			if (random.nextBoolean()) {
				g2.setColor(getRandColor(100, 180));
			}
			int xx = ((w - random.nextInt(10)) / verifySize) * i;
			int yy = h / 4 + fontSize / 2 - h / 20 - (i - verifySize / 2);
			AffineTransform affine = new AffineTransform();
			affine.setToRotation(Math.PI / 5 * random.nextDouble() * (random.nextBoolean() ? 1 : -1), xx + fontSize / 2, yy - fontSize / 2);
			g2.setTransform(affine);
			g2.drawChars(chars, i, 1, xx, yy);
		}

		chars = ("请 " + waitMinute + "分后再试").toCharArray();
		verifySize = chars.length;
		for (int i = 0; i < verifySize; i++) {
			if (random.nextBoolean()) {
				g2.setColor(getRandColor(100, 180));
			}
			int xx = ((w - random.nextInt(10)) / verifySize) * i;
			int yy = h * 3 / 4 + fontSize / 2 - h / 20 - (i - verifySize / 2);
			AffineTransform affine = new AffineTransform();
			affine.setToRotation(Math.PI / 5 * random.nextDouble() * (random.nextBoolean() ? 1 : -1), xx + fontSize / 2, yy - fontSize / 2);
			g2.setTransform(affine);
			g2.drawChars(chars, i, 1, xx, yy);
		}

		g2.dispose();

		return image;
		//ImageIO.write(image, "jpg", os);
	}


	private static Color getRandColor(int fc, int bc) {
		if (fc > 255)
			fc = 255;
		if (bc > 255)
			bc = 255;
		int r = fc + random.nextInt(bc - fc);
		int g = fc + random.nextInt(bc - fc);
		int b = fc + random.nextInt(bc - fc);
		return new Color(r, g, b);
	}


	private static int getRandomIntColor() {
		int[] rgb = getRandomRgb();
		int color = 0;
		for (int c : rgb) {
			color = color << 8;
			color = color | c;
		}
		return color;
	}


	private static int[] getRandomRgb() {
		int[] rgb = new int[3];
		for (int i = 0; i < 3; i++) {
			rgb[i] = random.nextInt(255);
		}
		return rgb;
	}


	private static void shear(Graphics g, int w1, int h1, Color color) {
		shearX(g, w1, h1, color);
		shearY(g, w1, h1, color);
	}


	private static void shearX(Graphics g, int w1, int h1, Color color) {
		boolean borderGap = true;
		/*
		 * 正弦型函数解析式：y=Asin（ωx+φ）+h
		 * 各常数值对函数图像的影响：
		 * φ（初相位）：决定波形与X轴位置关系或横向移动距离（左加右减）
		 * ω：决定周期（最小正周期T=2π/|ω|）
		 * A：决定峰值（即纵向拉伸压缩的倍数）
		 * h：表示波形在Y轴的位置关系或纵向移动距离（上加下减）
		 * 
		 * 一周的弧度数为2πr/r=2π，360°角=2π弧度，因此，1弧度约为57.3°，
		 * 即57°17'44.806''，1°为π/180弧度，近似值为0.01745弧度
		 */
		double period = (random.nextInt(4) + 1) * h1 / 2; // 周期：像素
		double amplitude = random.nextInt(h1 / 25) + h1 / 50 + 1;//振幅：像素
		double phase = random.nextInt(360);//相位：角度
		for (int i = 0; i < h1; i++) {
			double d = amplitude * Math.sin(2 * Math.PI * i / period + Math.PI * phase / 180);
			g.copyArea(0, i, w1, 1, (int) d, 0);
			if (borderGap) {
				g.setColor(color);
				g.drawLine(0, i, (int) d, i);
				g.drawLine(w1 + (int) d, i, w1, i);
			}
		}

	}


	private static void shearY(Graphics g, int w1, int h1, Color color) {
		boolean borderGap = true;

		double period = (random.nextInt(3) + 1.5) * w1 / 3; // 周期：像素
		double amplitude = random.nextInt(w1 / 60) + w1 / 50 + 1;//振幅：像素
		double phase = random.nextInt(360);//相位：角度

		for (int i = 0; i < w1; i++) {
			double d = amplitude * Math.sin(2 * Math.PI * i / period + Math.PI * phase / 180);
			g.copyArea(i, 0, 1, h1, 0, (int) d);
			if (borderGap) {
				g.setColor(color);
				g.drawLine(i, (int) d, i, 0);
				g.drawLine(i, (int) d + h1, i, h1);
			}

		}

	}


	public static void main(String[] args) throws IOException {
		File dir = new File("F:/verifies");
		if (dir.exists() && dir.isDirectory()) {
			for (File f : dir.listFiles()) {
				if (f.isFile()) {
					f.delete();
				}
			}
		}
		int w = 220, h = 90;
		for (int i = 0; i < 100; i++) {
			String verifyCode = generateVerifyCode(4);
			File file = new File(dir, verifyCode + ".jpg");
			outputImage(w, h, file, verifyCode);
		}

		//		for (int i = 0; i < 50; i++) {
		//			String verifyCode = generateVerifyCode(4);
		//			File file = new File(dir, verifyCode + ".jpg");
		//			outputError(w, h, file, 2, 10, 5);
		//		}

		//		for (int i = 0; i < 100; i++) {
		//			String verifyCode = generateVerifyCode(4);
		//			File file = new File(dir, verifyCode + ".gif");
		//			outputGIF(w, h, file, verifyCode, 5);
		//		}
	}
}
