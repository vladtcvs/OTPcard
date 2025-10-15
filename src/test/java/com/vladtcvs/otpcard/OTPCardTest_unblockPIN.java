package com.vladtcvs.otpcard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.*;

import javacard.framework.*;


public class OTPCardTest_unblockPIN {
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
        byte[] apdu_bad = {(byte)0x00, 0x05, 0x00, 0x00, 15, 6, '1', '2', '3', '4', '5', '5', 7, '7', '6', '5', '4', '3', '2', '1'};
        byte[] apdu_good = {(byte)0x00, 0x05, 0x00, 0x00, 15, 6, '1', '2', '3', '4', '5', '6', 7, '7', '6', '5', '4', '3', '2', '1'};
        byte[] apdu_unlock = {(byte)0x00, 0x06, 0x00, 0x00, 9, 8, '1', '2', '3', '4', '5', '6', '7', '8'};

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

        // Unblock pin
        resp = sim.transmitCommand(apdu_unlock);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);

        // new attempt
        resp = sim.transmitCommand(apdu_good);
        assertArrayEquals(new byte[]{(byte)0x90, (byte)0x00}, resp);
    }

    @Test
    public void Admin_lock() {
        // Send APDU
        byte[] apdu_bad = {(byte)0x00, 0x05, 0x00, 0x00, 15, 6, '1', '2', '3', '4', '5', '5', 7, '7', '6', '5', '4', '3', '2', '1'};
        byte[] apdu_good = {(byte)0x00, 0x05, 0x00, 0x00, 15, 6, '1', '2', '3', '4', '5', '6', 7, '7', '6', '5', '4', '3', '2', '1'};
        byte[] apdu_unlock_bad = {(byte)0x00, 0x06, 0x00, 0x00, 9, 8, '1', '2', '3', '4', '5', '6', '7', '7'};
        byte[] apdu_unlock_good = {(byte)0x00, 0x06, 0x00, 0x00, 9, 8, '1', '2', '3', '4', '5', '6', '7', '8'};

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

        // Unblock pin
        resp = sim.transmitCommand(apdu_unlock_bad);
        assertArrayEquals(new byte[]{(byte)0x69, (byte)0x82}, resp);

        // Unblock pin - 2 attempt
        resp = sim.transmitCommand(apdu_unlock_bad);
        assertArrayEquals(new byte[]{(byte)0x69, (byte)0x82}, resp);

        // Unblock pin - 3 attempt
        resp = sim.transmitCommand(apdu_unlock_bad);
        assertArrayEquals(new byte[]{(byte)0x69, (byte)0x82}, resp);

        // Unblock pin - good admin pin but locked
        resp = sim.transmitCommand(apdu_unlock_good);
        assertArrayEquals(new byte[]{(byte)0x69, (byte)0x83}, resp);
    }
}
