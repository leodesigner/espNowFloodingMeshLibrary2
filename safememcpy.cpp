

char *memcpyS(char *dest, int destsz, const char *src, int count)
{
  int i = 0;
  for (i = 0; (i < count) && (i < destsz); i++)
  {
    dest[i] = src[i];
  }
  return &dest[i];
}
