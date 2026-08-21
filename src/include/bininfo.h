#ifndef __BININFO_H__
#define __BININFO_H__
#ifdef __cplusplus
extern "C" {
#endif
    //
    // (i): Gives bininfo library version.
    //
    const char *bininfo_version(void);

    //
    // (i): Gives analyze as json.
    //
    const char *bininfo_analyze_json(const char *filename);    

    //
    // (i): Free's output (json/xml).
    //
    void bininfo_free(void *ptr);
#ifdef __cplusplus
}
#endif
#endif