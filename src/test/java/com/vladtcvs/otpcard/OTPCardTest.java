package com.vladtcvs.otpcard;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.*;
import com.vladtcvs.otpcard.OTPCard;

import javacard.framework.*;
//import javax.smartcardio.*;

public class OTPCardTest {

    private Simulator sim;
    private AID aid;

    @BeforeEach
    void setup() {
        Simulator sim = new Simulator();
        // Install and select
        AID appletAID = AIDUtil.create("A000000002020101");
        byte[] params = {(byte)0x08, // AID len
                         (byte)0xA0, 0x00, 0x00, 0x00, 0x02, 0x02, 0x01, 0x01, // AID
                         0x01, // CI len
                         0x00, // CI data
                         0x04,  // AD len
                         0x08, 0x08, 0x06, 0x06 // AD
                        };
        sim.installApplet(appletAID, OTPCard.class, params, (short)0, (byte)params.length);
        sim.selectApplet(appletAID);
    }
/*
    @Test
    public void GetINFO_Test() {
        // Send APDU
        byte[] apdu = {(byte)0x00, 0x08, 0x00, 0x00, 0x01, 0x00};
        byte[] resp = sim.transmitCommand(apdu);
        System.out.print("Response: ");
        for (int i = 0; i < resp.length; i++)
            System.out.print(String.format("%02X ", resp[i]));
        System.out.println("");
    }
        */
}
