//
//  ViewController.swift
//  SwiftEncryptDemo
//
//  Created by 侯仲祥 on 2020/7/27.
//  Copyright © 2020 houZhongXiang. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        
        let targetStr = "1234567"
        
        print("32位小写加密：" + targetStr.DDMD5Encrypt())

        print("32位大写加密：" + targetStr.DDMD5Encrypt(.uppercase32))
        
        print("16位小写加密：" + targetStr.DDMD5Encrypt(.lowercase16))

        print("16位大写加密：" + targetStr.DDMD5Encrypt(.uppercase16))
        
        print("DES加密字符串：" + targetStr.DDEncrypt())
        
        print("DES解密字符串：" + targetStr.DDEncrypt().DDDecrypt())
        
    }


}

