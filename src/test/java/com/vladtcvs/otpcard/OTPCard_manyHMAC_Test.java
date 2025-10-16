package com.vladtcvs.otpcard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.*;

import javacard.framework.*;


public class OTPCard_manyHMAC_Test {
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
    public void Test() {
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

        byte[] apdu_pin = {(byte)0x00, 0x42, 0x00, 0x00, 7, 6, '1', '2', '3', '4', '5', '6'};
        resp = sim.transmitCommand(apdu_pin);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);

        byte[] apdu2 = {(byte)0x00, 0x03, 0x00, 0x00, 18,
                        0,
                        10, 'S', 'E', 'C', 'R', 'E', 'T', 'A', 'B', 'C', 'D',
                        4, 'N', 'A', 'M', 'E',
                        1};
        resp = sim.transmitCommand(apdu2);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);

        for (int i = 0; i < 1000000; i++) {
            
            byte[] apdu3 = {(byte)0x00, 0x02, 0x00, 0x00, 1,
                            0};
            resp = sim.transmitCommand(apdu3);
            assertArrayEquals(new byte[]{0x01, 0x04, 'N', 'A', 'M', 'E', 0x01, (byte)0x90, (byte)0x00}, resp);

            int challenge = i;
            byte[] ch = {0,0,0,0,0,0,0,0};
            for (int j = 0; j < 8; j++) {
                ch[j] = (byte)((challenge >> (8*j)) & 0xFF);
            }
            byte[] apdu4 = {(byte)0x00, 0x01, 0x00, 0x00, 10,
                            0,
                            8, ch[0], ch[1], ch[2], ch[3], ch[4], ch[5], ch[6], ch[7]};
                
            resp = sim.transmitCommand(apdu4);
            assert(resp.length == 22);
            assert(resp[20] == (byte)0x90);
            assert(resp[21] == (byte)0x00);
        }
    }
}
