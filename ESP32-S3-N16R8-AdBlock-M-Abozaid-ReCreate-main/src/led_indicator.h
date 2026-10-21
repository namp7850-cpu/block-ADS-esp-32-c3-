#pragma once
#include <stdint.h>

void led_indicator_init();
void led_indicator_update();
void led_indicator_trigger(bool blocked);
void led_indicator_trigger_new_client();
void led_indicator_set_brightness(uint8_t brightness);

uint8_t led_indicator_get_brightness();
