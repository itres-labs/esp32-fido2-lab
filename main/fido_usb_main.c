/*
 * ESP32-S3 USB-FIDO2 LAB, ESP-IDF 5.5-era + esp_tinyusb 2.3.0.
 * Version 0.3: CTAP2, ES256, clientPIN, credProtect and AES-GCM root wrapping.
 * Experimental research firmware; do not use for production accounts.
 */
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "driver/gpio.h"
#include "bootloader_random.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "class/hid/hid_device.h"
#include "ctaphid.h"
#include "fido_crypto.h"
#include "fido_pin.h"

static const char *TAG="fido_lab";
#if defined(CONFIG_FIDO_BOARD_LILYGO) || defined(CONFIG_FIDO_BOARD_WAVESHARE)
#define PIN_USER_PRESENCE GPIO_NUM_0 /* Compartido con BOOT: requiere precauciones */
#else
#define PIN_USER_PRESENCE GPIO_NUM_41
#endif
static QueueHandle_t usb_incoming;

/* Usage Page 0xF1D0, Usage 0x01, FIDO Input 0x20 / Output 0x21.
 * 64 octetos por report, sin Report ID. */
static const uint8_t fido_report_desc[]={
    0x06,0xd0,0xf1,   /* Usage Page (FIDO Alliance) */
    0x09,0x01,        /* Usage (U2F Authenticator Device) */
    0xa1,0x01,        /* Collection (Application) */
    0x09,0x20,        /*   Usage Input Report Data */
    0x15,0x00,        /*   Logical Min 0 */
    0x26,0xff,0x00,   /*   Logical Max 255 */
    0x75,0x08,        /*   Report Size 8 */
    0x95,0x40,        /*   Report Count 64 */
    0x81,0x02,        /*   Input (Data, Var, Abs) */
    0x09,0x21,        /*   Usage Output Report Data */
    0x75,0x08,        /*   Report Size 8: repetir para python-fido2 */
    0x95,0x40,        /*   Report Count 64 */
    0x91,0x02,        /*   Output (Data, Var, Abs) */
    0xc0              /* End Collection */
};

#define CONFIG_DESC_LEN (TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN)
static const uint8_t fido_config_desc[]={
    TUD_CONFIG_DESCRIPTOR(1,1,0,CONFIG_DESC_LEN,0x00,100),
    TUD_HID_INOUT_DESCRIPTOR(0,0,HID_ITF_PROTOCOL_NONE,sizeof(fido_report_desc),0x01,0x81,64,5)
};

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance) {
    (void)instance;
    return fido_report_desc;
}
uint16_t tud_hid_get_report_cb(uint8_t instance,uint8_t report_id,
                               hid_report_type_t report_type,uint8_t *buffer,uint16_t reqlen) {
    (void)instance;(void)report_id;(void)report_type;(void)buffer;(void)reqlen;
    return 0; /* Este perfil no admite GET_REPORT */
}
void tud_hid_set_report_cb(uint8_t instance,uint8_t report_id,
                           hid_report_type_t report_type,uint8_t const *buffer,uint16_t bufsize) {
    (void)instance;(void)report_type;
    /* No confiar en tamaños enviados por host ni bloquear tarea USB. */
    if (report_id!=0 || bufsize!=CTAPHID_FRAME_SIZE || !usb_incoming) return;
    (void)xQueueSend(usb_incoming,buffer,0);
}

static uint32_t rnd32(void *ctx) {
    (void)ctx;
    return esp_random();
}
static void usb_send(const uint8_t frame[CTAPHID_FRAME_SIZE],void *ctx) {
    (void)ctx;
    if (!tud_mounted()) return;
    /* CTAPHID produce reports de longitud fija sin byte de Report ID. */
    for (unsigned retry=0;retry<1500 && tud_mounted();retry++) {
        if (tud_hid_ready() && tud_hid_report(0,frame,CTAPHID_FRAME_SIZE)) return;
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    ESP_LOGW(TAG,"USB TX timeout: host desconectado u ocupado");
}
void app_main(void) {
    gpio_config_t button={
        .pin_bit_mask=1ULL<<PIN_USER_PRESENCE,
        .mode=GPIO_MODE_INPUT,
        .pull_up_en=GPIO_PULLUP_ENABLE,
        .pull_down_en=GPIO_PULLDOWN_DISABLE,
        .intr_type=GPIO_INTR_DISABLE
    };
    ESP_ERROR_CHECK(gpio_config(&button));
    usb_incoming=xQueueCreate(32,CTAPHID_FRAME_SIZE);
    if (!usb_incoming) {ESP_LOGE(TAG,"Sin RAM para USB RX");abort();}

    /* Mantener la fuente física de entropía activa sin radios/ADC. */
    bootloader_random_enable();
    if(!fc_init()){
        ESP_LOGE(TAG,"Error en NVS: NO se borran secretos automáticamente");
        abort();
    }
    fp_init();
    ctaphid_t hid;
    ctaphid_init(&hid,usb_send,rnd32,NULL);

    tinyusb_config_t cfg=TINYUSB_DEFAULT_CONFIG();
    cfg.descriptor.full_speed_config=fido_config_desc;
    ESP_ERROR_CHECK(tinyusb_driver_install(&cfg));
    ESP_LOGW(TAG,"LAB ONLY: PIN-BASED AES-GCM, ROOT LOCKED UNTIL CLIENTPIN TOKEN");

    uint8_t rx[CTAPHID_FRAME_SIZE];
    bool was_pressed=(gpio_get_level(PIN_USER_PRESENCE)==0);
    uint32_t last_press_ms=0;
    while (true) {
        if (xQueueReceive(usb_incoming,rx,pdMS_TO_TICKS(10))==pdTRUE) {
            ctaphid_receive(&hid,rx,(uint32_t)(esp_timer_get_time()/1000));
        }
        ctaphid_tick(&hid,(uint32_t)(esp_timer_get_time()/1000));
        /* Comprobación de cableado, todavía NO equivale a User Presence de CTAP. */
        bool pressed=(gpio_get_level(PIN_USER_PRESENCE)==0);
        uint32_t now=(uint32_t)(esp_timer_get_time()/1000);
        if (pressed && !was_pressed && (uint32_t)(now-last_press_ms)>75u){
            last_press_ms=now;
            ctaphid_touch(&hid,now);
        }
        was_pressed=pressed;
    }
}
