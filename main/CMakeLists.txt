idf_component_register(SRCS "fido_usb_main.c" "ctaphid.c" "cbor_min.c" "fido_engine.c" "fido_crypto.c" "fido_pin.c"
                       INCLUDE_DIRS "."
                       REQUIRES esp_tinyusb esp_driver_gpio bootloader_support esp_hw_support esp_timer nvs_flash mbedtls)
