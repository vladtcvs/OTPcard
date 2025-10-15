package com.vladtcvs.otpcard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.*;

import javacard.framework.*;

public class OTPCardTest_getInfo {

    private Simulator sim;

    @BeforeEach
    void setup() {
        sim = new Simulator();
        // Install and select
        AID appletAID = AIDUtil.create("A000000002020101");
        byte[] params = {(byte)0x08, // AID len
                         (byte)0xA0, 0x00, 0x00, 0x00, 0x02, 0x02, 0x01, 0x01, // AID
                         0x01, // CI len
                         0x00, // CI data
                         0x08,  // AD len
                         0x08, 0x08, 0x03, 0x03, 0x21, 0x22, 0x23, 0x24 // AD
                        };
        sim.installApplet(appletAID, OTPCard.class, params, (short)0, (byte)params.length);
        sim.selectApplet(appletAID);
    }

    @Test
    public void GetINFO_Test() {
        // Send APDU
        byte[] apdu = {(byte)0x00, 0x08, 0x00, 0x00, 5, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] resp = sim.transmitCommand(apdu);
        assertArrayEquals(new byte[]{(byte)0x08,
                                     (byte)0x08,
                                     64,
                                     1, // SHA-1
                                     0, // SHA-256
                                     0, // SHA-512
                                     0x21, 0x22, 0x23, 0x24,
                                     (byte)0x90, 0x00}, resp);
    }
}

