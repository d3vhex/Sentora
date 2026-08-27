/**
 * Save a response body to a file.
 *
 * The object URL is revoked afterwards. Without that, every report a session
 * downloads stays in memory until the tab closes - and a PDF of a busy estate
 * is not small.
 *
 * The server sends `Content-Disposition`, and that is the name used when it
 * is readable: it carries the timestamp the report was generated at, which is
 * the part somebody filing it needs. `fallback` covers the case where a proxy
 * strips the header.
 */
export function saveBlobResponse(
  response: { data: Blob; headers?: Record<string, any> },
  fallback: string,
): void {
  const disposition = String(
    response.headers?.['content-disposition'] ??
    response.headers?.['Content-Disposition'] ?? '',
  );
  const match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disposition);
  const name = match ? decodeURIComponent(match[1]) : fallback;

  const url = URL.createObjectURL(response.data);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
