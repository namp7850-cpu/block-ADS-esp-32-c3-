#include "led_indicator.h"
#include <Adafruit_NeoPixel.h>

#define LED_PIN         48
#define NUM_LEDS        1
#define BLINK_MS        10

static Adafruit_NeoPixel led(NUM_LEDS, LED_PIN, NEO_GRB + NEO_KHZ800);
static uint8_t brightness = 128;

enum LedState { LED_IDLE, LED_RED, LED_GREEN, LED_PURPLE };
static LedState state = LED_IDLE;
static LedState queued = LED_IDLE;
static uint32_t blinkStart = 0;

static void setColor(uint8_t r, uint8_t g, uint8_t b) {
    uint8_t br = brightness;
    led.setPixelColor(0, led.Color(r * br / 255, g * br / 255, b * br / 255));
    led.show();
}

void led_indicator_init() {
    led.begin();
    led.setBrightness(255);
    led.clear(); led.show();
    Serial.println("[led] WS2812 on GPIO48 ready");
}

void led_indicator_update() {
    if (state == LED_IDLE) return;
    if (millis() - blinkStart >= BLINK_MS) {
        state = LED_IDLE;
        if (queued != LED_IDLE) {
            LedState next = queued;
            queued = LED_IDLE;
            blinkStart = millis();
            state = next;
            switch (next) {
                case LED_RED:    setColor(255,0,0); break;
                case LED_GREEN:  setColor(0,255,0); break;
                case LED_PURPLE: setColor(200,0,255); break;
                default: break;
            }
        } else {
            setColor(0,0,0);
        }
    }
}

static void blink(LedState s) {
    if (state == LED_IDLE) {
        blinkStart = millis();
        state = s;
        switch (s) {
            case LED_RED:    setColor(255,0,0); break;
            case LED_GREEN:  setColor(0,255,0); break;
            case LED_PURPLE: setColor(200,0,255); break;
            default: break;
        }
    } else {
        queued = s;
    }
}

void led_indicator_trigger(bool blocked) {
    blink(blocked ? LED_RED : LED_GREEN);
}

void led_indicator_trigger_new_client() {
    blink(LED_PURPLE);
}

void led_indicator_set_brightness(uint8_t br) {
    brightness = br;
    led.setBrightness(255);
    Serial.printf("[led] brightness=%d\n", br);
}

uint8_t led_indicator_get_brightness() { return brightness; }
