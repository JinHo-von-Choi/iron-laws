package demo;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;

@RestController
public class LegacyController {
    private final MemberMapper memberMapper;
    private final OtpService otpService;
    private final SmsService smsService;
    private final PayoutMapper payoutMapper;

    public LegacyController(MemberMapper m, OtpService o, SmsService s, PayoutMapper p) {
        this.memberMapper = m; this.otpService = o; this.smsService = s; this.payoutMapper = p;
    }

    // 1. ID만으로 로그인 세션 생성, 실패 횟수 초기화
    @SessionExclude
    @PostMapping("/user/changePwLater")
    public String changeLater(@RequestParam String userId, HttpSession session) {
        Member member = memberMapper.selectMember(userId);
        memberMapper.resetLoginFailCount(userId);
        session.setAttribute("LOGIN_USER", member);
        return "ok";
    }

    // 2. 로그인 없이 OTP 비밀키 응답
    @SessionExclude
    @GetMapping("/otp/service")
    public OtpInfo otpInfo(@RequestParam String userId) {
        OtpInfo info = otpService.findOrIssue(userId);
        return info; // info.otpSecret 포함
    }

    // 3. OTP 인증번호 확인, 횟수 제한 없음
    @SessionExclude
    @PostMapping("/otp/verify")
    public boolean verify(@RequestParam String userId, @RequestParam String code) {
        return otpService.verifyOtpCode(userId, code);
    }

    // 4. 2단계 인증 대상을 요청 값으로 정함
    @PostMapping("/sso/sendSms")
    public void sendSms(@RequestParam String userId, HttpSession session) {
        smsService.sendSmsCode(userId);
    }

    // 5. 전환 토큰만으로 세션 생성
    @GetMapping("/v2/switch")
    public String switchIn(@RequestParam String userId, @RequestParam String token, HttpSession session) {
        Member member = memberMapper.selectMember(userId);
        if (token.equals(member.getSwitchToken())) {
            session.setAttribute("LOGIN_USER", member);
        }
        return "redirect:/v2/main";
    }

    // 6. 소속 확인 없는 조회, 건수 상한 없음
    @GetMapping("/payout/list")
    public Object payoutList(@RequestParam String mid, @RequestParam int size) {
        return payoutMapper.selectPayoutList(mid, size);
    }

    // 7. GET으로 계정 전환
    @GetMapping("/account/switchUser")
    public String switchUser(@RequestParam String targetId, HttpSession session) {
        session.setAttribute("LOGIN_USER", memberMapper.selectMember(targetId));
        return "ok";
    }

}
