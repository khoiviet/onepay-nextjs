import crypto from "node:crypto";

/**
 * Cấu hình kết nối cổng thanh toán OnePay (VPC v2).
 */
export interface OnePayConfig {
  paymentUrl: string;
  merchantId: string;
  accessCode: string;
  hashCode: string;
}

/**
 * Các loại kênh thẻ OnePay hỗ trợ (theo tham số vpc_CardList).
 */
export type OnePayCardType = "DOMESTIC" | "INTERNATIONAL" | "AMEX" | "ALL";

/**
 * Danh sách mô tả chi tiết mã phản hồi từ cổng OnePay (vpc_TxnResponseCode).
 */
export const ONEPAY_RESPONSE_CODES: Record<string, string> = {
  "0": "Giao dịch thành công (Approved)",
  "1": "Ngân hàng từ chối giao dịch (Bank Declined)",
  "3": "Không nhận được phản hồi từ ngân hàng (No Reply from Bank)",
  "4": "Giao dịch hết hạn chờ thanh toán (Expired)",
  "5": "Số dư tài khoản không đủ để thanh toán (Insufficient Funds)",
  "6": "Lỗi từ chối từ ngân hàng phát hành thẻ (Card Issuer Declined)",
  "7": "Lỗi xử lý giao dịch tại ngân hàng (Processing Error)",
  "8": "Ngân hàng không hỗ trợ dịch vụ thanh toán trực tuyến (Service Not Supported)",
  "9": "Thẻ hoặc tài khoản ngân hàng không hợp lệ (Invalid Card or Account)",
  "10": "Thẻ đã hết hạn sử dụng (Card Expired)",
  "11": "Thẻ chưa đăng ký dịch vụ thanh toán Internet Banking (Not Registered)",
  "12": "Ngày phát hành hoặc ngày hết hạn của thẻ không đúng (Invalid Date)",
  "13": "Vượt quá hạn mức giao dịch trong ngày (Daily Limit Exceeded)",
  "21": "Số tiền trong tài khoản không đủ để thanh toán (Insufficient Balance)",
  "22": "Thông tin tài khoản ngân hàng không hợp lệ (Invalid Account Info)",
  "23": "Thẻ bị khóa hoặc tài khoản bị phong tỏa (Account Locked)",
  "24": "Thông tin thẻ không chính xác (Card Info Mismatch)",
  "25": "Mã xác thực OTP không đúng hoặc quá thời gian nhập (Invalid/Expired OTP)",
  "99": "Người dùng đã hủy bỏ giao dịch (User Cancelled)",
  "B": "Giao dịch đang chờ xác thực bảo mật 3D-Secure (Pending 3D-Secure)",
  "F": "Xác thực 3D-Secure không thành công (3D-Secure Failed)",
  "U": "Chờ xác nhận từ ngân hàng (Pending Bank Confirmation)",
};

/**
 * Tra cứu thông điệp tiếng Việt giải thích cho khách hàng từ mã phản hồi OnePay.
 */
export function getOnePayResponseMessage(code: string | null | undefined): string {
  if (!code) return "Không xác định được trạng thái giao dịch";
  return ONEPAY_RESPONSE_CODES[code.trim()] ?? `Giao dịch không thành công (Mã lỗi: ${code})`;
}

/**
 * Lấy cấu hình OnePay từ biến môi trường (.env / .env.local).
 */
export function getOnePayConfig(): OnePayConfig {
  return {
    paymentUrl: process.env.ONEPAY_PAYMENT_URL?.trim() || "https://mtf.onepay.vn/paygate/vpcpay.op",
    merchantId: process.env.ONEPAY_MERCHANT_ID?.trim() || "TESTONEPAY31",
    accessCode: process.env.ONEPAY_ACCESS_CODE?.trim() || "6BEB2566",
    hashCode: process.env.ONEPAY_HASH_CODE?.trim() || "6D0870CDE5F24F34F3915FB0045120D6",
  };
}

/**
 * Lấy giá trị tham số vpc_CardList theo loại thẻ chọn.
 */
export function cardListFromType(type?: OnePayCardType): string | undefined {
  switch (type) {
    case "DOMESTIC":
      return "DOMESTIC,QR";
    case "INTERNATIONAL":
      return "VC,MC,JC,CUP";
    case "AMEX":
      return "AE";
    case "ALL":
    default:
      return undefined;
  }
}

/**
 * Chuyển secret key sang Buffer:
 * - Chuỗi Hex chẵn ký tự (chuẩn OnePay Hash Code, ví dụ 32 hoặc 64 ký tự hex) -> Buffer.from(hex, 'hex')
 * - Fallback chuỗi thường -> Buffer.from(utf8)
 */
export function parseHashCodeToBuffer(hashCode: string): Buffer {
  const clean = hashCode.trim();
  if (/^[0-9a-fA-F]+$/.test(clean) && clean.length % 2 === 0) {
    return Buffer.from(clean, "hex");
  }
  return Buffer.from(clean, "utf-8");
}

/**
 * Tạo chữ ký vpc_SecureHash theo chuẩn OnePay VPC v2:
 * 1. Chỉ lấy các trường bắt đầu bằng "vpc_" hoặc "user_", có giá trị khác rỗng.
 * 2. Loại trừ "vpc_SecureHash" và "vpc_SecureHashType".
 * 3. Sắp xếp các tham số theo thứ tự alphabet mã ASCII của key.
 * 4. Ghép nối thành chuỗi "key1=value1&key2=value2...".
 * 5. Băm HMAC-SHA256 và xuất chuỗi Hex in hoa (UPPERCASE).
 */
export function createOnePaySecureHash(
  params: Record<string, string | number | undefined | null>,
  hashCode: string,
): string {
  const filteredKeys = Object.keys(params)
    .filter((key) => {
      if (!key.startsWith("vpc_") && !key.startsWith("user_")) return false;
      if (key.toLowerCase() === "vpc_securehash" || key.toLowerCase() === "vpc_securehashtype") return false;
      const val = params[key];
      return val !== undefined && val !== null && String(val).trim() !== "";
    })
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  const stringToSign = filteredKeys.map((key) => `${key}=${params[key]}`).join("&");
  const keyBuffer = parseHashCodeToBuffer(hashCode);
  return crypto.createHmac("sha256", keyBuffer).update(stringToSign).digest("hex").toUpperCase();
}

/**
 * Dữ liệu đầu vào để tạo URL thanh toán OnePay.
 */
export interface CreateOnePayUrlOptions {
  orderCode: string;
  amount: number;
  returnUrl: string;
  callbackUrl?: string;
  merchTxnRef?: string;
  ipAddress?: string;
  cardType?: OnePayCardType;
  title?: string;
  againLink?: string;
  locale?: "vn" | "en";
  customerPhone?: string;
  customerEmail?: string;
}

/**
 * Tạo URL chuyển hướng khách hàng sang cổng OnePay để thanh toán.
 */
export function buildOnePayPaymentUrl(
  options: CreateOnePayUrlOptions,
  configOverride?: Partial<OnePayConfig>,
): {
  url: string;
  merchTxnRef: string;
  secureHash: string;
  params: Record<string, string>;
} {
  const config = { ...getOnePayConfig(), ...configOverride };

  // Mã giao dịch: nếu không truyền vào thì tạo mã ngẫu nhiên duy nhất tối đa 40 ký tự
  const merchTxnRef =
    options.merchTxnRef?.trim() ||
    `XT${Date.now()}${crypto.randomBytes(4).toString("hex")}`.slice(0, 40);

  // Số tiền OnePay tính theo đơn vị hào (VND * 100)
  const amountInCents = Math.round(options.amount) * 100;

  const rawParams: Record<string, string> = {
    vpc_Version: "2",
    vpc_Command: "pay",
    vpc_Currency: "VND",
    vpc_Locale: options.locale || "vn",
    vpc_Merchant: config.merchantId,
    vpc_AccessCode: config.accessCode,
    vpc_MerchTxnRef: merchTxnRef,
    vpc_OrderInfo: options.orderCode.trim(),
    vpc_Amount: String(amountInCents),
    vpc_ReturnURL: options.returnUrl.trim(),
    vpc_TicketNo: options.ipAddress?.trim() || "127.0.0.1",
  };

  if (options.callbackUrl?.trim()) {
    rawParams.vpc_CallbackURL = options.callbackUrl.trim();
  }

  const cardList = cardListFromType(options.cardType);
  if (cardList) {
    rawParams.vpc_CardList = cardList;
  }

  if (options.title?.trim()) {
    rawParams.Title = options.title.trim();
  }

  if (options.againLink?.trim()) {
    rawParams.AgainLink = options.againLink.trim();
  }

  if (options.customerPhone?.trim()) {
    rawParams.user_Phone = options.customerPhone.trim();
  }

  if (options.customerEmail?.trim()) {
    rawParams.user_Email = options.customerEmail.trim();
  }

  // Tính toán chữ ký vpc_SecureHash
  const secureHash = createOnePaySecureHash(rawParams, config.hashCode);
  rawParams.vpc_SecureHash = secureHash;

  // Dựng URL chuyển hướng
  const urlObj = new URL(config.paymentUrl);
  for (const [key, value] of Object.entries(rawParams)) {
    urlObj.searchParams.set(key, value);
  }

  return {
    url: urlObj.toString(),
    merchTxnRef,
    secureHash,
    params: rawParams,
  };
}

/**
 * Kết quả xác thực chữ ký và thông tin giao dịch trả về từ OnePay.
 */
export interface OnePayVerifyResult {
  isValid: boolean;
  isSuccess: boolean;
  responseCode: string;
  responseMessage: string;
  orderInfo: string;
  merchTxnRef: string;
  amountVND: number;
  transactionNo: string | null;
  cardType: string | null;
  cardNum: string | null;
  authorizeId: string | null;
  rawParams: Record<string, string>;
}

/**
 * Xác thực dữ liệu trả về từ OnePay (áp dụng cho cả Return URL và IPN webhook).
 */
export function verifyOnePayCallback(
  query: Record<string, string | string[] | undefined> | URLSearchParams,
  configOverride?: Partial<OnePayConfig>,
): OnePayVerifyResult {
  const config = { ...getOnePayConfig(), ...configOverride };

  // Chuẩn hoá query params thành Record<string, string>
  const params: Record<string, string> = {};
  if (query instanceof URLSearchParams) {
    query.forEach((val, key) => {
      params[key] = val;
    });
  } else {
    for (const [key, val] of Object.entries(query)) {
      if (val !== undefined && val !== null) {
        params[key] = Array.isArray(val) ? val[0] : String(val);
      }
    }
  }

  // Tìm chữ ký OnePay gửi về (không phân biệt chữ hoa chữ thường)
  const secureHashKey = Object.keys(params).find(
    (k) => k.toLowerCase() === "vpc_securehash",
  );
  const incomingSecureHash = secureHashKey ? params[secureHashKey].trim() : "";

  // Tính chữ ký kỳ vọng
  const calculatedHash = createOnePaySecureHash(params, config.hashCode);

  // So sánh chữ ký
  const isValid =
    incomingSecureHash.length > 0 &&
    calculatedHash.toUpperCase() === incomingSecureHash.toUpperCase();

  const responseCode = params.vpc_TxnResponseCode?.trim() || "";
  const isSuccess = isValid && responseCode === "0";

  // Số tiền trả về chia 100 để quy đổi về VNĐ
  const rawAmount = Number(params.vpc_Amount || 0);
  const amountVND = Number.isFinite(rawAmount) ? Math.floor(rawAmount / 100) : 0;

  return {
    isValid,
    isSuccess,
    responseCode,
    responseMessage: getOnePayResponseMessage(responseCode),
    orderInfo: params.vpc_OrderInfo?.trim() || "",
    merchTxnRef: params.vpc_MerchTxnRef?.trim() || "",
    amountVND,
    transactionNo: params.vpc_TransactionNo?.trim() || null,
    cardType: params.vpc_Card?.trim() || null,
    cardNum: params.vpc_CardNum?.trim() || null,
    authorizeId: params.vpc_AuthorizeId?.trim() || null,
    rawParams: params,
  };
}
