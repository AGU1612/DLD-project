#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "mfrc522.h"

#define READER_COUNT 8
#define SECRET_KEY "LCK9X3K7"
#define STATUS_PRINT_INTERVAL_MS 5000  // Print status every 5 seconds

const uint SELECT_PINS[3] = {0, 1, 2}; // GP0 (LSB), GP1, GP2 (MSB)

// Array to track health status of each scanner
bool scanner_health[READER_COUNT] = {0};
// Array to track last status print time for each scanner
uint32_t last_status_print[READER_COUNT] = {0};

// Core1 GPIO pins for TRUE case (binary output + activate)
#define GPIO_TRUE_LSB   6
#define GPIO_TRUE_MID   7
#define GPIO_TRUE_MSB   8
#define GPIO_TRUE_ACT   9

// Core1 GPIO pins for FALSE case (binary output + activate)
#define GPIO_FALSE_LSB  10
#define GPIO_FALSE_MID  11
#define GPIO_FALSE_MSB  12
#define GPIO_FALSE_ACT  13

void core1_entry() {
    // Initialize GPIO pins for TRUE case (GP6, GP7, GP8, GP9)
    gpio_init(GPIO_TRUE_LSB);
    gpio_set_dir(GPIO_TRUE_LSB, GPIO_OUT);
    gpio_put(GPIO_TRUE_LSB, 0);
    
    gpio_init(GPIO_TRUE_MID);
    gpio_set_dir(GPIO_TRUE_MID, GPIO_OUT);
    gpio_put(GPIO_TRUE_MID, 0);
    
    gpio_init(GPIO_TRUE_MSB);
    gpio_set_dir(GPIO_TRUE_MSB, GPIO_OUT);
    gpio_put(GPIO_TRUE_MSB, 0);
    
    gpio_init(GPIO_TRUE_ACT);
    gpio_set_dir(GPIO_TRUE_ACT, GPIO_OUT);
    gpio_put(GPIO_TRUE_ACT, 0);
    
    // Initialize GPIO pins for FALSE case (GP14, GP15, GP16, GP17)
    gpio_init(GPIO_FALSE_LSB);
    gpio_set_dir(GPIO_FALSE_LSB, GPIO_OUT);
    gpio_put(GPIO_FALSE_LSB, 0);
    
    gpio_init(GPIO_FALSE_MID);
    gpio_set_dir(GPIO_FALSE_MID, GPIO_OUT);
    gpio_put(GPIO_FALSE_MID, 0);
    
    gpio_init(GPIO_FALSE_MSB);
    gpio_set_dir(GPIO_FALSE_MSB, GPIO_OUT);
    gpio_put(GPIO_FALSE_MSB, 0);
    
    gpio_init(GPIO_FALSE_ACT);
    gpio_set_dir(GPIO_FALSE_ACT, GPIO_OUT);
    gpio_put(GPIO_FALSE_ACT, 0);
    
    char buffer[256];
    
    while (1) {
        // Read a line from stdin
        if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
            // Parse the format: KEY:index:true or KEY:index:false
            char key[32];
            int index;
            char value[10];
            
            if (sscanf(buffer, "%[^:]:%d:%s", key, &index, value) == 3) {
                // Extract binary bits from index (0-7, using 3 bits)
                int bit0 = (index & 1);          // LSB
                int bit1 = ((index >> 1) & 1);   // Mid
                int bit2 = ((index >> 2) & 1);   // MSB
                
                if (strcmp(value, "true") == 0) {
                    // Set binary on TRUE pins (GP6, GP7, GP8)
                    gpio_put(GPIO_TRUE_LSB, bit0);
                    gpio_put(GPIO_TRUE_MID, bit1);
                    gpio_put(GPIO_TRUE_MSB, bit2);
                    
                    // Pulse activate pin for 5ms
                    gpio_put(GPIO_TRUE_ACT, 1);
                    sleep_ms(5);
                    gpio_put(GPIO_TRUE_ACT, 0);
                    
                } else if (strcmp(value, "false") == 0) {
                    // Set binary on FALSE pins (GP14, GP15, GP16)
                    gpio_put(GPIO_FALSE_LSB, bit0);
                    gpio_put(GPIO_FALSE_MID, bit1);
                    gpio_put(GPIO_FALSE_MSB, bit2);
                    
                    // Pulse activate pin for 5ms
                    gpio_put(GPIO_FALSE_ACT, 1);
                    sleep_ms(5);
                    gpio_put(GPIO_FALSE_ACT, 0);
                }
            }
        }
        sleep_us(100); // Small delay to avoid busy-waiting
    }
}

int main() {
    stdio_init_all();

    while (!stdio_usb_connected()) {
        sleep_ms(100);
    }

    // Launch core1 for serial input handling
    multicore_launch_core1(core1_entry);

    // Init select pins for core0
    for (int p = 0; p < 3; p++) {
        gpio_init(SELECT_PINS[p]);
        gpio_set_dir(SELECT_PINS[p], GPIO_OUT);
        gpio_put(SELECT_PINS[p], 0);
    }

    MFRC522Ptr_t readers[READER_COUNT];
    for (int i = 0; i < READER_COUNT; i++) {
        // Set binary on select pins
        gpio_put(SELECT_PINS[0], (i & 1));
        gpio_put(SELECT_PINS[1], ((i >> 1) & 1));
        gpio_put(SELECT_PINS[2], ((i >> 2) & 1));

        readers[i] = MFRC522_Init();
        PCD_Init(readers[i], spi0, 15); // CS pin
        
        // Health check during initialization
        sleep_ms(100); // Wait for initialization to complete
        
        if (PCD_CheckHealth(readers[i])) {
            scanner_health[i] = true;
            printf("%s:%d:ok\n", SECRET_KEY, i);
        } else {
            scanner_health[i] = false;
            printf("%s:%d:disconnected\n", SECRET_KEY, i);
        }
        last_status_print[i] = to_ms_since_boot(get_absolute_time());
    }

    while (1) {
        for (int i = 0; i < READER_COUNT; i++) {
            // Set binary on select pins
            gpio_put(SELECT_PINS[0], (i & 1));
            gpio_put(SELECT_PINS[1], ((i >> 1) & 1));
            gpio_put(SELECT_PINS[2], ((i >> 2) & 1));
            
            sleep_ms(1); // Let pins settle

            uint32_t current_time = to_ms_since_boot(get_absolute_time());
            bool status_changed = false;

            // Check if scanner is healthy before attempting to scan
            if (!PCD_CheckHealth(readers[i])) {
                // Scanner is faulty/disconnected
                if (scanner_health[i]) {
                    // State change: healthy -> disconnected
                    scanner_health[i] = false;
                    printf("%s:%d:disconnected\n", SECRET_KEY, i);
                    last_status_print[i] = current_time;
                    status_changed = true;
                } else {
                    // Still disconnected - print every 5 seconds
                    if ((current_time - last_status_print[i]) >= STATUS_PRINT_INTERVAL_MS) {
                        printf("%s:%d:disconnected\n", SECRET_KEY, i);
                        last_status_print[i] = current_time;
                    }
                }
                continue; // Skip this scanner
            } else {
                // Scanner is healthy
                if (!scanner_health[i]) {
                    // State change: disconnected -> healthy
                    // Re-initialize the scanner after reconnection
                    PCD_Init(readers[i], spi0, 15);
                    sleep_ms(50);
                    scanner_health[i] = true;
                    printf("%s:%d:ok\n", SECRET_KEY, i);
                    last_status_print[i] = current_time;
                    status_changed = true;
                } else {
                    // Still healthy - print every 5 seconds
                    if ((current_time - last_status_print[i]) >= STATUS_PRINT_INTERVAL_MS) {
                        printf("%s:%d:ok\n", SECRET_KEY, i);
                        last_status_print[i] = current_time;
                    }
                }
            }

            // Only scan if scanner is healthy
            if (!PICC_IsNewCardPresent(readers[i])) {
                continue;
            }
            if (!PICC_ReadCardSerial(readers[i])) {
                continue;
            }

            // Print SECRET_KEY:index:UID
            printf("%s:%d:", SECRET_KEY, i);
            for (int j = 0; j < readers[i]->uid.size; j++) {
                printf("%02X", readers[i]->uid.uidByte[j]);
                if (j < readers[i]->uid.size - 1) printf(":");
            }
            printf("\n");

            PICC_HaltA(readers[i]);
        }
    }

    return 0;
}