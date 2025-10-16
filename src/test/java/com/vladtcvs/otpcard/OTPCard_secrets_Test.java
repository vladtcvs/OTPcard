package com.vladtcvs.otpcard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;

public class OTPCard_secrets_Test {

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
    public void store() {
        byte[] apdu_pin = {(byte)0x00, 0x42, 0x00, 0x00, 7, 6, '1', '2', '3', '4', '5', '6'};

        byte[] resp = sim.transmitCommand(apdu_pin);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);

        byte[] apdu = {(byte)0x00, 0x03, 0x00, 0x00, 14, 0, 6, 'S', 'E', 'C', 'R', 'E', 'T', 4, 'N', 'A', 'M', 'E', 1};
        resp = sim.transmitCommand(apdu);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);
    }

    @Test
    public void delete() {
        byte[] apdu_pin = {(byte)0x00, 0x42, 0x00, 0x00, 7, 6, '1', '2', '3', '4', '5', '6'};
        byte[] resp = sim.transmitCommand(apdu_pin);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);

        byte[] apdu1 = {(byte)0x00, 0x03, 0x00, 0x00, 14, 0, 6, 'S', 'E', 'C', 'R', 'E', 'T', 4, 'N', 'A', 'M', 'E', 1};
        resp = sim.transmitCommand(apdu1);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);

        byte[] apdu2 = {(byte)0x00, 0x04, 0x00, 0x00, 1, 0};
        resp = sim.transmitCommand(apdu2);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);

        byte[] apdu3 = {(byte)0x00, 0x02, 0x00, 0x00, 1, 0};
        resp = sim.transmitCommand(apdu3);
        assertArrayEquals(new byte[]{0x00, 0x00, 0x00, (byte)0x90, (byte)0x00}, resp);
    }

    @Test
    public void status() {
        byte[] apdu_pin = {(byte)0x00, 0x42, 0x00, 0x00, 7, 6, '1', '2', '3', '4', '5', '6'};
        byte[] resp = sim.transmitCommand(apdu_pin);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);

        byte[] apdu1 = {(byte)0x00, 0x03, 0x00, 0x00, 14, 0, 6, 'S', 'E', 'C', 'R', 'E', 'T', 4, 'N', 'A', 'M', 'E', 1};
        resp = sim.transmitCommand(apdu1);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);

        byte[] apdu2 = {(byte)0x00, 0x02, 0x00, 0x00, 1, 0};
        resp = sim.transmitCommand(apdu2);
        assertArrayEquals(new byte[]{0x01, 0x04, 'N', 'A', 'M', 'E', 0x01, (byte)0x90, (byte)0x00}, resp);
    }

    @Test
    public void hmacSHA1() {
        byte[] apdu_pin = {(byte)0x00, 0x42, 0x00, 0x00, 7, 6, '1', '2', '3', '4', '5', '6'};
        byte[] resp = sim.transmitCommand(apdu_pin);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);

        byte[] apdu1 = {(byte)0x00, 0x03, 0x00, 0x00, 14, 0, 6, 'S', 'E', 'C', 'R', 'E', 'T', 4, 'N', 'A', 'M', 'E', 1};
        resp = sim.transmitCommand(apdu1);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);

        byte[] apdu2 = {(byte)0x00, 0x01, 0x00, 0x00, 11, 0, 9, 'C', 'H', 'A', 'L', 'L', 'E', 'N', 'G', 'E'};
        resp = sim.transmitCommand(apdu2);
        assertArrayEquals(new byte[]{(byte)0x51, (byte)0xF8, (byte)0x9F, (byte)0x78, (byte)0xDA,
                                     (byte)0x44, (byte)0x4A, (byte)0xA4, (byte)0x10, (byte)0x40,
                                     (byte)0x4C, (byte)0xF7, (byte)0xC0, (byte)0x27, (byte)0x6A,
                                     (byte)0x71, (byte)0x40, (byte)0xC6, (byte)0xF0, (byte)0xBD,
                                     (byte)0x90, (byte)0x00}, resp);
    }
}
