package com.vladtcvs.otpcard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.*;

import javacard.framework.*;

public class OTPCard_PIN_Test {

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
    public void Success() {
        // Send APDU
        byte[] apdu_good1 = {(byte)0x00, 0x42, 0x00, 0x00, 7, 6, '1', '2', '3', '4', '5', '6'};
        byte[] apdu_good2 = {(byte)0x00, 0x05, 0x00, 0x00, 7, 6, '6', '5', '4', '3', '2', '1'};
        byte[] apdu_good3 = {(byte)0x00, 0x42, 0x00, 0x00, 7, 6, '6', '5', '4', '3', '2', '1'};

        // Send APDU - change pin
        byte[] resp = sim.transmitCommand(apdu_good1);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);

        // new attempt with new pin
        resp = sim.transmitCommand(apdu_good2);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);

        // new attempt with new pin
        resp = sim.transmitCommand(apdu_good3);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);
    }

    @Test
    public void Wrong_PIN() {
        // Send APDU
        byte[] apdu = {(byte)0x00, 0x42, 0x00, 0x00, 7, 6, '1', '2', '3', '4', '5', '5'};
        byte[] resp = sim.transmitCommand(apdu);
        assertArrayEquals(new byte[]{(byte)0x69, (byte)0x82}, resp);
    }

    @Test
    public void Wrong_length_1() {
        // Send APDU
        byte[] apdu1 = {(byte)0x00, 0x42, 0x00, 0x00, 7, 6, '1', '2', '3', '4', '5', '6'};
        byte[] apdu2 = {(byte)0x00, 0x05, 0x00, 0x00, 8, 8, '7', '6', '5', '4', '3', '2', '1'};
        byte[] resp = sim.transmitCommand(apdu1);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);
        resp = sim.transmitCommand(apdu2);
        assertArrayEquals(new byte[]{(byte)0x67, (byte)0x00}, resp);
    }

    @Test
    public void Wrong_length_2() {
        // Send APDU
        byte[] apdu1 = {(byte)0x00, 0x42, 0x00, 0x00, 7, 6, '1', '2', '3', '4', '5', '6'};
        byte[] apdu2 = {(byte)0x00, 0x05, 0x00, 0x00, 8, 6, '7', '6', '5', '4', '3', '2', '1'};
        byte[] resp = sim.transmitCommand(apdu1);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);
        resp = sim.transmitCommand(apdu2);
        assertArrayEquals(new byte[]{(byte)0x67, (byte)0x00}, resp);
    }

    @Test
    public void Wrong_pin_lock() {
        // Send APDU
        byte[] apdu_bad = {(byte)0x00, 0x42, 0x00, 0x00, 7, 6, '1', '2', '3', '4', '5', '5'};
        byte[] apdu_good = {(byte)0x00, 0x42, 0x00, 0x00, 7, 6, '1', '2', '3', '4', '5', '6'};

        // Send APDU - wrong pin
        byte[] resp = sim.transmitCommand(apdu_bad);
        assertArrayEquals(new byte[]{(byte)0x69, (byte)0x82}, resp);

        // Send APDU - second attempt
        resp = sim.transmitCommand(apdu_bad);
        assertArrayEquals(new byte[]{(byte)0x69, (byte)0x82}, resp);

        // Send APDU - third attempt
        resp = sim.transmitCommand(apdu_bad);
        assertArrayEquals(new byte[]{(byte)0x69, (byte)0x82}, resp);

        // Send APDU - 4-th attempt - should fail even with good pin
        resp = sim.transmitCommand(apdu_good);
        assertArrayEquals(new byte[]{(byte)0x69, (byte)0x83}, resp);
    }
}
