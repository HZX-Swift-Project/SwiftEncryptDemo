//
//  String+DDEncrypt.swift
//  MD5EncrptDemo
//
//  Created by 遇见 on 2020/7/15.
//  Copyright © 2020 yuJian. All rights reserved.
//

import Foundation
import CommonCrypto

// MARK: ------------------- MD5加密
extension String {
    /// MD5加密类型
    enum MD5EncryptType {
        /// 32位小写
        case lowercase32
        /// 32位大写
        case uppercase32
        /// 16位小写
        case lowercase16
        /// 16位大写
        case uppercase16
    }
    
    /// MD5加密 默认是32位小写加密
    /// - Parameter type: 加密类型
    /// - Returns: 加密字符串
    func DDMD5Encrypt(_ md5Type: MD5EncryptType = .lowercase32) -> String {
        guard self.count > 0 else {
            print("⚠️⚠️⚠️md5加密无效的字符串⚠️⚠️⚠️")
            return ""
        }
        /// 1.把待加密的字符串转成char类型数据 因为MD5加密是C语言加密
        let cCharArray = self.cString(using: .utf8)
        /// 2.创建一个字符串数组接受MD5的值
        var uint8Array = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        /// 3.计算MD5的值
        /*
         第一个参数:要加密的字符串
         第二个参数: 获取要加密字符串的长度
         第三个参数: 接收结果的数组
         */
        CC_MD5(cCharArray, CC_LONG(cCharArray!.count - 1), &uint8Array)
        
        switch md5Type {
        /// 32位小写
        case .lowercase32:
            return uint8Array.reduce("") { $0 + String(format: "%02x", $1)}
        /// 32位大写
        case .uppercase32:
            return uint8Array.reduce("") { $0 + String(format: "%02X", $1)}
        /// 16位小写  tip：16位实际上是从 32 位字符串中，取中间的第 9 位到第 24 位的部分
        case .lowercase16:
            let tempStr = uint8Array.reduce("") { $0 + String(format: "%02x", $1)}
            return tempStr.getString(startIndex: 8, endIndex: 24)
        /// 16位大写
        case .uppercase16:
            let tempStr = uint8Array.reduce("") { $0 + String(format: "%02X", $1)}
            return tempStr.getString(startIndex: 8, endIndex: 24)
        }
    }
}

// MARK: ------------------- DES加密
enum CryptoAlgorithm {
    case AES,AES128,DES,DES3,CAST,RC2,RC4,Blowfish
    var algorithm : CCAlgorithm {
        var result : UInt32 = 0
        switch self {
        case .AES:
            result = UInt32(kCCAlgorithmAES)
        case .AES128:
            result = UInt32(kCCAlgorithmAES128)
        case .DES:
            result = UInt32(kCCAlgorithmDES)
        case .DES3:
            result = UInt32(kCCAlgorithm3DES)
        case .CAST:
            result = UInt32(kCCAlgorithmCAST)
        case .RC2:
            result = UInt32(kCCAlgorithmRC2)
        case .RC4:
            result = UInt32(kCCAlgorithmRC4)
        case .Blowfish:
            result = UInt32(kCCAlgorithmBlowfish)
        }
        return CCAlgorithm(result)
    }
    
    var keyLength : Int {
        var result : Int = 0
        switch self {
        case .AES:
            result = kCCKeySizeAES128
        case .AES128:
            result = kCCKeySizeAES256
        case .DES:
            result = kCCKeySizeDES
        case .DES3:
            result = kCCKeySize3DES
        case .CAST:
            result = kCCKeySizeMaxCAST
        case .RC2:
            result = kCCKeySizeMaxRC2
        case .RC4:
            result = kCCKeySizeMaxRC4
        case .Blowfish:
            result = kCCKeySizeMaxBlowfish
        }
        return Int(result)
    }
    
    var cryptLength:Int {
        var result:Int = 0
        switch self {
        case .AES:
            result = kCCKeySizeAES128
        case .AES128:
            result = kCCBlockSizeAES128
        case .DES:
            result = kCCBlockSizeDES
        case .DES3:
            result = kCCBlockSize3DES
        case .CAST:
            result = kCCBlockSizeCAST
        case .RC2:
            result = kCCBlockSizeRC2
        case .RC4:
            result = kCCBlockSizeRC2
        case .Blowfish:
            result = kCCBlockSizeBlowfish
        }
        return Int(result)
    }
    
}

extension String {
    
    /// 字符串加密
    /// - Parameter type: 加密算法类型 默认是DES加密
    /// - Returns: 加密以后的字符串
    func DDEncrypt(_ type: CryptoAlgorithm = .DES) -> String {
        return DDDefaultEncrypt(operationType: CCOperation(kCCEncrypt), algorithm: type)
    }
    
    /// 字符串解密
    /// - Parameter type: 解密算法类型 默认是DES加密
    /// - Returns: 加密以后的字符串
    func DDDecrypt(_ type: CryptoAlgorithm = .DES) -> String {
        return DDDefaultEncrypt(operationType: CCOperation(kCCDecrypt), algorithm: type)
    }
    
    /// 加密解密方法
    /// - Parameters:
    ///   - operationType: 加密或者解密
    ///   - algorithm: 算法类型
    /// - Returns: 加密或者解密结果
    private func DDDefaultEncrypt(operationType: CCOperation, algorithm: CryptoAlgorithm) -> String {
        /// 后台对应的加密key
        let encryptKey = "b" //这个是跟后台商量的key 不能为空
        let encryptKeyData: Data! = encryptKey.data(using: .utf8, allowLossyConversion: false)!
        let encryptKeyBytes = UnsafeRawPointer((encryptKeyData as NSData).bytes)
        
        /// 后台对应的加密IV
        let encryptIV = "" //这个是跟后台商量的iv偏移量
        let encryptIVData = encryptIV.data(using: .utf8)!
        let encryptIVDataBytes = UnsafeRawPointer((encryptIVData as NSData).bytes)
        
        /// 需要加密或者解密的数据的数据
        var targetData: Data  = Data()
        if operationType == CCOperation(kCCEncrypt) {
            /// 加密
            targetData = self.data(using: .utf8)!
        } else {
            /// 解密
            guard let tempData = Data(base64Encoded: self.data(using: .utf8)!, options: .ignoreUnknownCharacters) else {
                print("😂😂 解密的时候报错 😂😂")
                return ""
            }
            targetData = tempData
        }
        let dataLength = Int(targetData.count)
        let dataBytes = UnsafeRawPointer((targetData as NSData).bytes)
        
        /// 对应的输出的缓存数据
        var bufferData = Data(count: dataLength + algorithm.cryptLength)
        let bufferPointer = UnsafeMutableRawPointer(mutating: (bufferData as NSData).bytes)
        let bufferLength = size_t(bufferData.count)
        
        /// 开始进行加密或者解密
        var bytesDecrypted = Int(0)
        let cryptStatus = CCCrypt(operationType, // 加密类型  加密还是解密
            algorithm.algorithm, // 加密算法类型
            CCOptions(kCCOptionPKCS7Padding), // 填充方式，通常是kCCOptionPKCS7Padding，默认分组模式CBC。OC中提供两种模式：kCCOptionPKCS7Padding、kCCOptionECBMode
            encryptKeyBytes, // 秘钥的字节长度
            algorithm.keyLength, // 秘钥长度
            encryptIVDataBytes, // 可选初始化向量的字节
            dataBytes, // 加密数据内容的字节
            dataLength, // 加密数据内容的长度
            bufferPointer, // 输出缓冲数据
            bufferLength, // 输出缓冲长度
            &bytesDecrypted)
        
        if CCStatus(cryptStatus) == CCStatus(kCCSuccess) {
            /// 加密解密成功
            bufferData.count = bytesDecrypted
            if operationType == CCOperation(kCCEncrypt) {
                /// 加密
                return bufferData.base64EncodedString()
            } else {
                /// 解密
                return String(data: bufferData, encoding: .utf8) ?? ""
            }
        } else {
            /* 这里是加密或者解密返回的失败结果
            enum {
                kCCSuccess          = 0,
                kCCParamError       = -4300,
                kCCBufferTooSmall   = -4301,
                kCCMemoryFailure    = -4302,
                kCCAlignmentError   = -4303,
                kCCDecodeError      = -4304,
                kCCUnimplemented    = -4305
            };
            */
            print("😂😂😂加密或者解密失败了--Error: \(cryptStatus)")
            return ""
        }
    }
}

    
