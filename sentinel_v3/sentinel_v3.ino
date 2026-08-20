if (ftype == 0x00 && fsubtype == 0x0C) { // Deauth
  // ... existing deauth code ...
}
else if (ftype == 0x00 && fsubtype == 0x04) { // Probe Request
  portENTER_CRITICAL_ISR(&cntMux);
  cnt_probe++;
  int snap = cnt_probe;
  portEXIT_CRITICAL_ISR(&cntMux);

  if (snap >= PROBE_THRESHOLD) {
    ThreatAlert a;
    strlcpy(a.type, "PROBE_FLOOD", sizeof(a.type));
    fmtMAC(hdr->addr2, a.mac);
    a.rssi     = rssi;
    a.channel  = current_channel;
    a.count    = snap;

    BaseType_t woken = pdFALSE;
    xQueueSendFromISR(alertQueue, &a, &woken);

    portENTER_CRITICAL_ISR(&cntMux);
    cnt_probe = 0;
    portEXIT_CRITICAL_ISR(&cntMux);
  }
}