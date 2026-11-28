package demo; public interface OtpService { OtpInfo findOrIssue(String u); boolean verifyOtpCode(String u, String c); }
